# Splunk MCP WebUI

[![CI](https://github.com/MysticCoss/splunk-mcp-webui/actions/workflows/ci.yml/badge.svg)](https://github.com/MysticCoss/splunk-mcp-webui/actions/workflows/ci.yml)

MCP (Model Context Protocol) server cho Splunk — dựa trên các tool của Splunk MCP Server chính hãng, nhưng:

| | MCP chính hãng | Splunk MCP WebUI |
|---|---|---|
| Kết nối | splunkd REST API (port 8089) + token/app cài trong Splunk | **Splunk Web UI (port 8000)** — login bằng form như trình duyệt |
| Cấu hình | token, cert, app, roles... | **Chỉ 3 field: `splunk_url`, `username`, `password`** |
| Số tool | ~20 | **6 tool cốt lõi** |

Chỉ cần Splunk Web mở được là dùng được — không cần port quản trị 8089, không cần token, không cần cài app lên Splunk.

## Các tool

| Tool | Mô tả |
|---|---|
| `splunk_run_query` | Chạy SPL query, trả về kết quả JSON (mặc định 100 dòng, có `truncated` + `next_offset` để lấy trang tiếp; `_raw` tự cắt ở 1000 ký tự) |
| `splunk_get_job_results` | Lấy tiếp kết quả của 1 job đã chạy xong **theo sid** — phân trang khối lượng lớn mà không phải chạy lại search |
| `splunk_get_search_job_status` | Xem trạng thái 1 job (done/running/failed) và tổng số kết quả |
| `splunk_get_indexes` | Danh sách index dạng compact (tên, kích thước, số event, splunk_server...); `full: true` để lấy toàn bộ config |
| `splunk_get_index_info` | Thông tin chi tiết 1 index |
| `splunk_get_metadata` | Metadata `hosts` / `sources` / `sourcetypes` theo index và khoảng thời gian |

## Cài đặt

```powershell
git clone https://github.com/MysticCoss/splunk-mcp-webui
cd splunk-mcp-webui
pip install -r requirements.txt
```

Hoặc cài như package: `pip install git+https://github.com/MysticCoss/splunk-mcp-webui` — sau đó chạy bằng lệnh `splunk-mcp-webui`.

## Cấu hình

Copy `config.example.json` thành `config.json` rồi sửa. Client tìm config theo thứ tự:

1. Đường dẫn trong biến môi trường `SPLUNK_MCP_CONFIG` (nếu đặt)
2. `config.json` cạnh thư mục `splunk_mcp_webui/` (khi clone repo)
3. `~/.splunk-mcp/config.json` (tiện khi cài bằng `pip install git+...` — không có thư mục project)

```json
{
  "splunk_url": "https://splunk-cua-ban",
  "username": "admin",
  "password": "mat-khau"
}
```

> `config.json` chứa credential thật nên đã bị `.gitignore` loại khỏi repo — chỉ commit `config.example.json`.

Các key tùy chọn (đều có giá trị mặc định, không cần khai báo):

| Key | Mặc định | Mô tả |
|---|---|---|
| `locale` | `en-US` | Locale path của Splunk Web (`vi-VN`, `en-US`...) — tự detect khi có thể |
| `verify_ssl` | `false` | Xác thực chứng chỉ SSL — mặc định chấp nhận self-signed; đặt `true` để xác thực nghiêm ngặt hoặc đường dẫn CA bundle nội bộ |
| `read_only` | `true` | Chặn các SPL command sửa dữ liệu: `delete`, `outputlookup`, `collect`, `script`, `sendemail`... Đặt `false` để cho phép |
| `max_raw_chars` | `1000` | Giới hạn ký tự của field `_raw` trong kết quả search (0 = không giới hạn) |
| `request_timeout` | `60` | Timeout cho mỗi HTTP request (giây) |
| `search_timeout` | `300` | Timeout tối đa cho 1 search job (giây) |
| `poll_interval` | `1` | Chu kỳ poll trạng thái job (giây) |
| `default_row_limit` | `100` | Số dòng trả về mặc định của `splunk_run_query` |
| `max_row_limit` | `1000` | Số dòng tối đa mỗi lần fetch — kết quả nhiều hơn thì dùng `offset` để lấy trang tiếp |

## SSL self-signed

Mặc định client **chấp nhận mọi chứng chỉ SSL** — kể cả self-signed, cert nội bộ hay cert tự ký của Splunk:

```json
{
  "verify_ssl": false
}
```

Đây là giá trị mặc định, không cần khai báo trong `config.json`. Chỉ khi muốn xác thực chứng chỉ nghiêm ngặt thì mới đặt `true`, hoặc trỏ tới **CA bundle nội bộ** (hỗ trợ cert CA riêng của công ty):

```json
{
  "verify_ssl": "C:\\certs\\corp-ca.pem"
}
```

Đó là tất cả. Mọi thứ khác tự xử lý: tự detect `http/https`, locale (`en-US`...), session cookie, CSRF form-key, tự re-login khi session hết hạn, SSL self-signed được tự động chấp nhận.

> `splunk_url` chấp nhận mọi dạng: `splunk.corp.local`, `10.0.0.5:8000`, `http://10.0.0.5:8000`, `https://splunk.corp.local:8000/en-US`.
> Mật khẩu có thể đặt qua biến môi trường `SPLUNK_URL` / `SPLUNK_USERNAME` / `SPLUNK_PASSWORD` (ghi đè file) để không lưu plain-text. Đường dẫn config khác: `SPLUNK_MCP_CONFIG`.
> ⚠️ Khi `splunk_url` ghi rõ `https://`, client **không bao giờ** tự hạ cấp xuống HTTP — handshake TLS hỏng sẽ báo lỗi thay vì gửi mật khẩu plaintext.

## Bảo mật — dùng tài khoản quyền tối thiểu

`read_only: true` (mặc định) chặn các lệnh sửa dữ liệu (`delete`, `outputlookup`, `mcollect`, `dump`, `script`, `map`, `savedsearch`, macro...) — nhưng đây là **lớp bảo vệ best-effort**, không thay thế phân quyền của Splunk. Hãy tạo account MCP riêng với quyền tối thiểu:

- **Không có** capability `can_delete`
- **Không có** quyền `list_storage_passwords` (tránh lộ mật khẩu đã lưu qua lệnh `rest`)
- Giới hạn `srchIndexesAllowed` đúng các index cần đọc
- Giới hạn `srchJobsQuota` và `srchTimeWin` (cửa sổ thời gian tìm kiếm)

Ngoài ra lưu ý: nội dung log (có thể chứa PII/dữ liệu nhạy cảm) sẽ được gửi tới nhà cung cấp LLM qua MCP client — cân nhắc khi dùng với dữ liệu SOC nội bộ.

> SSO/SAML: login đi qua form local-credential (`loginType=splunk`) nên **hoạt động trên instance bật SSO** (kể cả Azure AD). Tuy nhiên account phải dùng xác thực local (username/password) — SAML-only/MFA-only không dùng được.

## Kiểm tra kết nối trước khi dùng

```powershell
python tests\test_real.py
```

## Đăng ký vào MCP client

### Claude Code

```powershell
claude mcp add splunk-webui -s user -- python C:\duong\dan\splunk-mcp-webui\run.py
```

- `-s user`: cài cấp user, dùng được cho mọi project trên máy. Bỏ tham số này thì chỉ áp dụng cho project hiện tại.
- Kiểm tra: mở Claude Code, gõ `/mcp` — phải thấy `splunk-webui` kèm 6 tool.

### Claude Desktop / opencode

Thêm vào file cấu hình MCP của client:

```json
{
  "mcpServers": {
    "splunk-webui": {
      "command": "python",
      "args": ["C:\\duong\\dan\\splunk-mcp-webui\\run.py"]
    }
  }
}
```

Chạy trực tiếp (stdio): `python run.py` hoặc `python -m splunk_mcp_webui`.

## Cách hoạt động

```
MCP client ──stdio──> run.py ──HTTP──> Splunk Web (port 8000)
                         │ 1. GET  /en-US/account/login        → cookie + CSRF
                         │ 2. POST /en-US/account/login        → session cookie
                         │ 3. POST /en-US/splunkd/__raw/services/search/jobs  → tạo job
                         │ 4. GET  /en-US/splunkd/__raw/services/search/jobs/{sid} → poll
                         │ 5. GET  .../{sid}/results           → kết quả JSON
```

Không dùng port 8089 — mọi REST call đi qua proxy `splunkd/__raw/` của chính Splunk Web (giống hệt khi bạn mở Search & Reporting trên trình duyệt).

## Test offline (không cần Splunk thật)

```powershell
python tests\test_offline.py       # 46 test: login cũ/mới, CSRF, guard, timeout, SSL fallback, concurrency...
python tests\test_config.py        # 12 test: validation config, env override, fail-loud
python tests\test_mcp_server.py    # test 6 tool qua giao thức MCP
```

License: MIT (xem `LICENSE`).

> Thư mục `ref\` (bản giải nén app MCP chính hãng làm tham chiếu schema) không được commit vào repo — tham khảo `splunk-mcp-server_200.tgz` từ SplunkBase nếu cần.
