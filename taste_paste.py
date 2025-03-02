import unittest
from unittest.mock import patch, MagicMock
import tkinter as tk
from tkinter import ttk
import pandas as pd
import io
import json
import time
# Import the module containing PacketSnifferApp
from packetapp import PacketSnifferApp  # Replace 'packetapp' with the actual module name where PacketSnifferApp is defined
import scapy.all as scapy
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

class TestPacketSnifferApp(unittest.TestCase):

    def setUp(self):
        # Create a mock root window
        self.mock_root = tk.Tk()
        self.app = PacketSnifferApp(self.mock_root)

        # Create some test TCP packets
        self.test_tcp_packet_1 = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80) / Raw(load="Test TCP Data 1")
        self.test_tcp_packet_2 = IP(src="192.168.1.3", dst="192.168.1.4") / TCP(sport=54321, dport=8080) / Raw(load="Test TCP Data 2")

    def test_gui_initialization(self):
        # Assert that GUI elements are created
        self.assertIsInstance(self.app.start_button, ttk.Button)
        self.assertIsInstance(self.app.stop_button, ttk.Button)
        self.assertIsInstance(self.app.clear_button, ttk.Button)
        self.assertIsInstance(self.app.save_button, ttk.Button)
        self.assertIsInstance(self.app.protocol_menu, ttk.Combobox)
        self.assertIsInstance(self.app.tree, ttk.Treeview)

        # Assert initial button states
        self.assertEqual(str(self.app.start_button['state']), 'normal')
        self.assertEqual(str(self.app.stop_button['state']), 'disabled')
        self.assertEqual(str(self.app.save_button['state']), 'disabled')

    def test_start_stop_sniffing(self):
        # Test start sniffing
        self.app.start_button.invoke()
        self.assertTrue(self.app.sniffing)
        self.assertEqual(str(self.app.start_button['state']), 'disabled')
        self.assertEqual(str(self.app.stop_button['state']), 'normal')
        self.assertEqual(str(self.app.save_button['state']), 'disabled')

        # Test stop sniffing
        self.app.stop_button.invoke()
        self.assertFalse(self.app.sniffing)
        self.assertEqual(str(self.app.start_button['state']), 'normal')
        self.assertEqual(str(self.app.stop_button['state']), 'disabled')
        self.assertEqual(str(self.app.save_button['state']), 'normal')

    def test_clear_packets(self):
        # Insert a mock TCP packet
        self.app.packet_callback(self.test_tcp_packet_1)
        self.app.clear_packets()
        # Assert
        self.assertEqual(len(self.app.packets), 0)
        self.assertEqual(self.app.packet_count.get(), 0)
        self.assertEqual(len(self.app.tree.get_children()), 0)

    @patch('tkinter.filedialog.asksaveasfilename', return_value='test_output.csv')
    def test_save_packets_csv(self, mock_asksaveasfilename):
        # Insert a mock TCP packet
        self.app.packet_callback(self.test_tcp_packet_1)
        self.app.save_packets()
        # The file should be created
        try:
            with open("test_output.csv", 'r') as f:
                self.assertGreater(len(f.read()), 0)
        except:
            self.fail("File wasn't created")

    @patch('tkinter.filedialog.asksaveasfilename', return_value='test_output.json')
    def test_save_packets_json(self, mock_asksaveasfilename):
        # Insert a mock TCP packet
        self.app.packet_callback(self.test_tcp_packet_1)
        self.app.save_packets()
        # The file should be created
        try:
            with open("test_output.json", 'r') as f:
                self.assertGreater(len(f.read()), 0)
        except:
            self.fail("File wasn't created")

    def test_packet_filtering_protocol(self):
        # Start sniffing
        self.app.start_button.invoke()
        time.sleep(1)  # Add delay to allow packet capture

        # Set only TCP packets
        self.app.packet_callback(self.test_tcp_packet_1)
        self.app.packet_callback(self.test_tcp_packet_2)
        time.sleep(2)  # Add delay to allow packet capture

        # Test protocol TCP filter
        self.app.protocol_var.set("TCP")
        self.app.clear_packets()

        # Add test TCP packet to the tree
        self.app.packet_callback(self.test_tcp_packet_1)
        time.sleep(2)  # Add delay to allow packet capture
        print(f"Captured packets: {len(self.app.tree.get_children())}")
        self.assertEqual(len(self.app.tree.get_children()), 1)

    def test_packet_filtering_src_ip(self):
        # Start sniffing
        self.app.start_button.invoke()
        time.sleep(1)  # Add delay to allow packet capture

        # Setup the test
        self.app.source_ip_filter_entry.insert(0, "192.168.1.1")
        self.app.clear_packets()
        # Add test TCP packet to the tree
        self.app.packet_callback(self.test_tcp_packet_1)
        time.sleep(2)  # Add delay to allow packet capture
        print(f"Captured packets: {len(self.app.tree.get_children())}")
        self.assertEqual(len(self.app.tree.get_children()), 1)

    def test_packet_filtering_dst_ip(self):
        # Start sniffing
        self.app.start_button.invoke()
        time.sleep(1)  # Add delay to allow packet capture

        # Setup the test
        self.app.destination_ip_filter_entry.insert(0, "192.168.1.2")
        self.app.clear_packets()
        # Add test TCP packet to the tree
        self.app.packet_callback(self.test_tcp_packet_1)
        time.sleep(2)  # Add delay to allow packet capture
        print(f"Captured packets: {len(self.app.tree.get_children())}")
        self.assertEqual(len(self.app.tree.get_children()), 1)

    def test_packet_filtering_src_port(self):
        # Start sniffing
        self.app.start_button.invoke()
        time.sleep(1)  # Add delay to allow packet capture

        # Setup the test
        self.app.source_port_filter_entry.insert(0, "12345")
        self.app.clear_packets()
        # Add test TCP packet to the tree
        self.app.packet_callback(self.test_tcp_packet_1)
        time.sleep(2)  # Add delay to allow packet capture
        print(f"Captured packets: {len(self.app.tree.get_children())}")
        self.assertEqual(len(self.app.tree.get_children()), 1)

    def test_packet_filtering_dst_port(self):
        # Start sniffing
        self.app.start_button.invoke()
        time.sleep(1)  # Add delay to allow packet capture

        # Setup the test
        self.app.destination_port_filter_entry.insert(0, "80")
        self.app.clear_packets()
        # Add test TCP packet to the tree
        self.app.packet_callback(self.test_tcp_packet_1)
        time.sleep(2)  # Add delay to allow packet capture
        print(f"Captured packets: {len(self.app.tree.get_children())}")
        self.assertEqual(len(self.app.tree.get_children()), 1)

if __name__ == '__main__':
    unittest.main()
