import os
import datetime
from pymavlink import mavutil

# Get the directory where bin_to_srt.py is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def format_srt_time(ms_total):
    seconds = int(ms_total // 1000)
    milliseconds = int(ms_total % 1000)
    minutes = int(seconds // 60)
    hours = int(minutes // 60)
    return f"{hours:02d}:{minutes % 60:02d}:{seconds % 60:02d},{milliseconds:03d}"

def convert_bin_to_srt(bin_file_path, output_srt_path, sample_interval_ms=1000):
    # Ensure full absolute path to the file
    if not os.path.isabs(bin_file_path):
        bin_file_path = os.path.join(SCRIPT_DIR, bin_file_path)

    if not os.path.exists(bin_file_path):
        raise FileNotFoundError(f"Binary log file not found at: {bin_file_path}")

    print(f"Opening binary log: {bin_file_path}")
    mlog = mavutil.mavlink_connection(bin_file_path)

    srt_entries = []
    entry_index = 1

    last_lat, last_lon, last_alt = 0.0, 0.0, 0.0
    last_roll, last_pitch, last_yaw = 0.0, 0.0, 0.0

    start_time_ms = None
    next_sample_time_ms = 0

    while True:
        msg = mlog.recv_match(type=['GPS', 'ATT'], blocking=False)
        if msg is None:
            break

        msg_type = msg.get_type()

        if msg_type == 'GPS':
            if hasattr(msg, 'Status') and msg.Status >= 3:
                last_lat = msg.Lat / 1e7
                last_lon = msg.Lng / 1e7
                last_alt = msg.Alt

        elif msg_type == 'ATT':
            last_roll = getattr(msg, 'Roll', 0.0)
            last_pitch = getattr(msg, 'Pitch', 0.0)
            last_yaw = getattr(msg, 'Yaw', 0.0)

        if hasattr(msg, 'TimeUS'):
            current_time_ms = msg.TimeUS / 1000.0

            if start_time_ms is None:
                start_time_ms = current_time_ms
                next_sample_time_ms = start_time_ms

            if current_time_ms >= next_sample_time_ms:
                relative_start_ms = next_sample_time_ms - start_time_ms
                relative_end_ms = relative_start_ms + sample_interval_ms

                start_str = format_srt_time(relative_start_ms)
                end_str = format_srt_time(relative_end_ms)

                telemetry_line = (
                    f"[latitude: {last_lat:.7f}] "
                    f"[longitude: {last_lon:.7f}] "
                    f"[altitude: {last_alt:.2f}m] "
                    f"[roll: {last_roll:.1f}] "
                    f"[pitch: {last_pitch:.1f}] "
                    f"[yaw: {last_yaw:.1f}]"
                )

                srt_block = (
                    f"{entry_index}\n"
                    f"{start_str} --> {end_str}\n"
                    f"{telemetry_line}\n\n"
                )

                srt_entries.append(srt_block)
                entry_index += 1
                next_sample_time_ms += sample_interval_ms

    output_full_path = os.path.join(SCRIPT_DIR, output_srt_path)
    with open(output_full_path, "w", encoding="utf-8") as srt_file:
        srt_file.writelines(srt_entries)

    print(f"Conversion complete! Created '{output_full_path}' with {len(srt_entries)} entries.")


if __name__ == "__main__":
    # If 00000024.BIN is in the same folder as bin_to_srt.py, pass just filename:
    convert_bin_to_srt(
        bin_file_path="00000024.BIN",
        output_srt_path="converted_telemetry.srt",
        sample_interval_ms=1000
    )