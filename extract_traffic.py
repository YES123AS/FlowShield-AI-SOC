from scapy.all import sniff, wrpcap
import os
import time

# 设置保存PCAP文件的文件夹
output_folder = "captured_traffic"
if not os.path.exists(output_folder):
    os.makedirs(output_folder)


# 定义抓包的回调函数
def packet_callback(packet):
    print(f"Captured packet: {packet.summary()}")


# 抓包并保存为PCAP文件
def capture_traffic(duration=10, output_file="capture.pcap"):
    # 开始抓包
    print(f"Starting capture for {duration} seconds...")
    packets = sniff(timeout=duration, prn=packet_callback)

    # 保存抓取的数据包到PCAP文件
    output_path = os.path.join(output_folder, output_file)
    wrpcap(output_path, packets)
    print(f"Capture complete. Saved to {output_path}")


if __name__ == "__main__":
    # 设置抓包时长和输出文件名
    capture_duration = 30  # 抓包时长（秒）
    output_filename = f"traffic_{int(time.time())}.pcap"  # 使用时间戳作为文件名

    # 开始抓包
    capture_traffic(duration=capture_duration, output_file=output_filename)