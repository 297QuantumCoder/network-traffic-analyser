
# Network Traffic Analyzer

Network Traffic Analyzer is a Python-based application that captures and analyzes network packets flowing through a network interface. It provides a user-friendly graphical interface for real-time packet monitoring and analysis.

## Features

- **Real-time Packet Analysis**: Capture and analyze network packets in real-time.
- **Packet Details**: View detailed information about captured packets, including source/destination IP addresses, protocols, and payload data.
- **Filtering**: Filter specific types of traffic (e.g., HTTP, DNS) for focused analysis.
- **Database Storage**: Save captured packet information to a SQLite database for further analysis and archival.

## Prerequisites

Before running the application, ensure you have the following installed:

- [Python 3.x](https://www.python.org/downloads/)
- Scapy library: `pip install scapy`

## Usage

1. **Clone the Repository**:

```bash
git clone https://github.com/297QuantumCoder/network-traffic-analyzer.git
```

2. **Navigate to the Project Directory**:

```bash
cd network-traffic-analyzer
```

3. **Run the Application**:

```bash
python main.py
```

4. **Start Capturing Packets**:
   - Click on the "Start Sniffing" button to begin capturing network packets.
   - Click on the "Stop Sniffing" button to stop capturing network packets.

5. **Analyze Packets**:
   - Analyze the captured packet information in the GUI.
   - View real-time updates and detailed packet information.


## Contributing

Contributions are welcome! If you'd like to contribute to this project, feel free to open a pull request or submit an issue.

## License

This project is licensed under the [MIT License](LICENSE).
```
