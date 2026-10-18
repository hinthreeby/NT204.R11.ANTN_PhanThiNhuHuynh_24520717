# Test T12: Idle Timeout

## Mục tiêu

Kiểm tra idle timeout cho cả UDP và TCP, việc xuất thông tin flow hết hạn và loại flow khỏi active-flow table.

## Input

Cấu hình mặc định:

- UDP idle timeout: 60 giây.
- TCP idle timeout: 300 giây.

Test tạo một UDP flow và một TCP flow, sau đó tạo các event có timestamp vượt quá timeout tương ứng.

Giữ nguyên 6 event và toàn bộ assertion cũ. `validate.py` còn kiểm tra ranh giới timeout, summary hai chiều, cấu hình TCP/UDP riêng, timeout bằng 0, cleanup lặp, tái sử dụng 5-tuple, timestamp lỗi/đi lùi, malformed/skip event, TCP CLOSED/RESET và EOF của JSONL/PCAP. Dữ liệu phụ được tạo trong bộ nhớ hoặc thư mục tạm và tự xóa sau khi chạy.

## Cơ chế cleanup

`FlowTracker.expire_idle_flows(current_time)` và `IDSPipeline.expire_idle_flows(current_time)` trả danh sách summary và xóa flow hết hạn, không cần packet mới hoặc flow key. Ví dụ với UDP `last_seen = 1000`, timeout 60 giây: gọi tại 1060 chưa hết hạn, gọi tại 1060.1 mới hết hạn.

Mốc thời gian phải cùng hệ thời gian với timestamp capture. Không tự dùng giờ hệ thống để so với PCAP lịch sử. Mốc không hợp lệ (`None`, chuỗi lỗi, boolean, số âm, NaN/Infinity) trả danh sách rỗng và giữ nguyên state; chuỗi số hợp lệ được chấp nhận.

Với event có timestamp hợp lệ, Flow Tracker kiểm tra cleanup trước bước xét flow key, kể cả event không thể track. Summary vẫn nằm trong `expired_flows` của event. Event bị pipeline skip vẫn trả `None` như trước và không âm thầm lấy mất summary; bên gọi có thể dùng API cleanup theo mốc thời gian để nhận summary.

Không có background scheduler hay flush tự động ở EOF. Đọc hết file không chứng minh đã vượt idle timeout. Bên gọi API chịu trách nhiệm thu thập/lưu các summary được trả về; event schema hiện có không đổi.

## Cách chạy

Chạy từ thư mục gốc repository.

```bash
python main.py --input TEST/BaiTap2/T12_idle_timeout/input.jsonl --output TEST/BaiTap2/T12_idle_timeout/events.jsonl
python TEST/BaiTap2/T12_idle_timeout/validate.py
```

## Kết quả mong đợi
- UDP flow hết hạn sau hơn 60 giây không hoạt động.
- TCP flow hết hạn sau hơn 300 giây không hoạt động.
- Flow hết hạn xuất hiện trong expired_flows.
- Flow hết hạn bị loại khỏi active-flow table.
- Khi cùng 5-tuple xuất hiện lại, một flow_id mới được tạo.
- Trước hoặc đúng ngưỡng timeout, flow còn active; chỉ hết hạn khi `current_time - last_seen > timeout`.
- Summary giữ nguyên counter, `start_time`, `last_seen`, `duration` của packet cuối; thời gian chờ idle không cộng vào duration.
- Với flow đang hoạt động hết hạn: `expired = true`, `close_reason = idle_timeout` và không còn trong active table.
- Cleanup lặp không xuất trùng summary. Connection mới bắt đầu lại counter và duration, không sửa object cũ.
- TCP đã CLOSED/RESET giữ lý do `tcp_closed`/`tcp_reset` khi cleanup, không bị đổi thành `idle_timeout`.
- Cấu hình kiểm thử riêng: UDP 2 giây, TCP 7 giây; có kiểm tra timeout 0.

## Kết quả thực tế
- Trạng thái: PASS
- UDP và TCP flow đều hết hạn đúng timeout.
- Flow summary được xuất trước khi loại khỏi active table.
- Khi traffic xuất hiện lại, cả hai tạo flow mới.
- Validator trả về T12 PASS.
- Đã chạy các kiểm tra mở rộng và xác nhận EOF JSONL/PCAP không tự làm flow hết hạn; `result.txt` ghi kết quả từng nhóm.
- Regression T07, T08, T09, T10, T11, T13, T14 đều PASS.

## Minh chứng
- input.jsonl
- events.jsonl
- validate.py
- result.txt

## Kết luận
Testcase PASS, idle timeout và flow expiration hoạt động đúng cho cả TCP và UDP.
