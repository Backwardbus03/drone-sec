import os
import datetime
from pymavlink import mavutil

# Get the directory where bin_to_srt.py is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def format_srt_time(ms_total):
    seconds, milliseconds = divmod(int(ms_total), 1000)
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d},{milliseconds:03d}"

def convert_bin_to_srt(bin_file_path, output_srt_path, sample_interval_ms=1000):
    # Ensure full absolute path to the file
    if not os.path.isabs(bin_file_path):
        bin_file_path = os.path.join(SCRIPT_DIR, bin_file_path)

    if not os.path.exists(bin_file_path):
        raise FileNotFoundError(f"Binary log file not found at: {bin_file_path}")

    output_full_path = os.path.join(SCRIPT_DIR, output_srt_path) if not os.path.isabs(output_srt_path) else output_srt_path

    print(f"Opening binary log: {bin_file_path}")
    mlog = mavutil.mavlink_connection(bin_file_path)

    entry_index = 1
    last_lat, last_lon, last_alt = 0.0, 0.0, 0.0
    last_roll, last_pitch, last_yaw = 0.0, 0.0, 0.0

    start_time_ms = None
    next_sample_time_ms = 0

    with open(output_full_path, "w", encoding="utf-8", buffering=65536) as srt_file:
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

                    srt_file.write(srt_block)
                    entry_index += 1
                    next_sample_time_ms += sample_interval_ms

    print(f"Conversion complete! Created '{output_full_path}' with {entry_index - 1} entries.")


if __name__ == "__main__":
    import sys
    bin_file = sys.argv[1] if len(sys.argv) > 1 else "00000024.BIN"
    out_file = sys.argv[2] if len(sys.argv) > 2 else "converted_telemetry.srt"
    convert_bin_to_srt(
        bin_file_path=bin_file,
        output_srt_path=out_file,
        sample_interval_ms=1000
    )