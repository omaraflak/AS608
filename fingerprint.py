from dataclasses import dataclass
import logging
import serial
import time
import math

# Packet Header
HEADER = bytes([0xEF, 0x01])

# Packet Identifiers
PID_CMD = 0x01
PID_DATA = 0x02
PID_ACK = 0x07
PID_EOD = 0x08

# Command Codes
CMD_VERIFY_PASSWORD = 0x13
CMD_READ_SYSTEM_PARAMETERS = 0x0f
CMD_TURN_ON_LED = 0x50
CMD_TURN_OFF_LED = 0x51
CMD_GET_ECHO = 0x53

# Confirmation Codes
ACK_SUCCESS = 0x00
ACK_RECEIVE_ERROR = 0x01
ACK_NO_FINGER = 0x02
ACK_ENROLL_FAILED = 0x03
ACK_DISTORTED_IMAGE = 0x06
ACK_BLURRY_IMAGE = 0x07
ACK_NOT_MATCHED = 0x08
ACK_NOT_FOUND = 0x09
ACK_NO_CHAR_FILE = 0x0A
ACK_PAGE_ID_OUT_OF_RANGE = 0x0B
ACK_INVALID_TEMPLATE = 0x0C
ACK_TEMPLATE_UPLOAD_FAILED = 0x0D
ACK_RECEIVE_PACKAGE_FAILED = 0x0E
ACK_IMAGE_UPLOAD_FAILED = 0x0F
ACK_DELETE_TEMPLATE_FAILED = 0x10
ACK_CLEAR_LIB_FAILED = 0x11
ACK_FAILED_TO_GENERATE_IMAGE = 0x15
ACK_ERROR_WRITING_FLASH = 0x18
ACK_INVALID_REGISTER = 0x1A
ACK_HANDSHAKE_SUCCESSFUL = 0x55


@dataclass
class SystemParameters:
    status_register: int
    system_identifier_code: int
    library_size: int
    security_level: int
    device_address: int
    data_packet_size: int
    baud_settings: int


@dataclass
class Package:
    header: bytes
    module_address: int
    pid: int
    length: int
    content: bytes
    checksum: bytes

    @property
    def confirmation_code(self) -> int:
        return self.content[0]


class FingerprintModule:
    def __init__(
        self,
        port: str,
        baudrate: int = 57600,
        module_address: int = 0xffffffff,
        timeout: float = 1
    ):
        self.port = port
        self.baudrate = baudrate
        self.module_address = module_address
        self.timeout = timeout
        self.ser: serial.Serial = None

    def connect(self) -> bool:
        try:
            self.ser = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                timeout=self.timeout
            )
            time.sleep(0.1)
            logging.debug(
                f"Connected to fingerprint module on {self.port} at {self.baudrate} bps.")
            return True
        except serial.SerialException as e:
            logging.error(f"Error connecting to serial port {self.port}: {e}")
            self.ser = None
            return False

    def disconnect(self):
        if self.ser and self.ser.is_open:
            self.ser.close()
            logging.debug("Disconnected from fingerprint module.")
        self.ser = None

    def get_echo(self) -> bool:
        request = self._make_data_package(bytes([CMD_GET_ECHO]))
        self._write(request)
        response = self._verify_ack(self.ser.read(12))
        return response and response.confirmation_code == ACK_HANDSHAKE_SUCCESSFUL

    def verify_password(self, password: int = 0) -> bool:
        password_bytes = password.to_bytes(4)
        request = self._make_data_package(bytes(
            [CMD_VERIFY_PASSWORD, *password_bytes]))
        self._write(request)
        response = self._verify_ack(self.ser.read(12))
        return response and response.confirmation_code == ACK_SUCCESS

    def read_system_parameters(self) -> SystemParameters | None:
        request = self._make_data_package(bytes([CMD_READ_SYSTEM_PARAMETERS]))
        self._write(request)

        response = self._verify_ack(self.ser.read(28))
        if not response:
            return None

        if response.confirmation_code == ACK_SUCCESS:
            logging.error(
                f"Expected confirmation code {ACK_SUCCESS}, but got {response.confirmation_code}. Content: {response.content}")
            return None

        data = response.content[1:]
        return SystemParameters(
            status_register=int.from_bytes(data[0:2]),
            system_identifier_code=int.from_bytes(data[2:4]),
            library_size=int.from_bytes(data[4:6]),
            security_level=int.from_bytes(data[6:8]),
            device_address=int.from_bytes(data[8:12]),
            data_packet_size=int.from_bytes(data[12:14]),
            baud_settings=int.from_bytes(data[14:16]),
        )

    def turn_on_led(self) -> bool:
        request = self._make_data_package(bytes([CMD_TURN_ON_LED]))
        self._write(request)
        response = self._verify_ack(self.ser.read(12))
        return response and response.confirmation_code == ACK_SUCCESS

    def turn_off_led(self) -> bool:
        request = self._make_data_package(bytes([CMD_TURN_OFF_LED]))
        self._write(request)
        response = self._verify_ack(self.ser.read(12))
        return response and response.confirmation_code == ACK_SUCCESS

    def _write(self, data: bytes) -> bool:
        count = self.ser.write(data)
        if count == len(data):
            return True

        logging.error(
            f"Expected to write {len(data)} bytes, but wrote {count}")
        return False

    def _make_data_package(self, content: bytes) -> bytes:
        return self._make_package(PID_CMD, content)

    def _make_package(self, pid: int, content: bytes) -> bytes:
        header = HEADER + self.module_address.to_bytes(4)
        length = len(content) + 2
        body = bytes([pid]) + length.to_bytes(2) + content
        checksum = self._compute_checksum(pid, length, content)
        package = header + body + checksum
        logging.debug(f"Built package: {package.hex(sep=' ')}")
        return package

    def _verify_ack(self, data: bytes) -> Package | None:
        package = FingerprintModule._parse_package(data)

        if not package:
            return None

        if package.module_address != self.module_address:
            logging.error(
                f"Expected header {self.module_address} but got {package.module_address}. Package: {data.hex(' ')}")
            return None

        if package.pid != PID_ACK:
            logging.error(
                f"Expected pid {PID_ACK} but got {package.pid}. Package: {data.hex(' ')}")
            return None

        return package

    @staticmethod
    def _parse_package(data: bytes) -> Package | None:
        package = Package(
            header=data[:2],
            module_address=int.from_bytes(data[2:6]),
            pid=data[6],
            length=int.from_bytes(data[7:9]),
            content=data[9:-2],
            checksum=data[-2:],
        )

        if package.header != HEADER:
            logging.error(
                f"Expected header {HEADER.hex()} but got {package.header.hex()}. Package: {data.hex(' ')}")
            return None

        checksum = FingerprintModule._compute_checksum(
            package.pid, package.length, package.content)

        if package.checksum != checksum:
            logging.error(
                f"Expected checksum {checksum.hex()} but got {package.checksum.hex()}. Package: {data.hex(' ')}")
            return None

        return package

    @staticmethod
    def _compute_checksum(pid: int, length: int, content: bytes) -> bytes:
        checksum = pid + length + sum(content)
        result = FingerprintModule._int_to_bytes(checksum)
        if len(result) == 1:
            return bytes([0x00, result[0]])
        return result[:2]

    @staticmethod
    def _int_to_bytes(integer_in: int) -> bytes:
        length = math.ceil(math.log(integer_in)/math.log(256))
        return integer_in.to_bytes(length)

# - memory is 512 bytes. 16 pages * 32 bytes. PS_WriteNotepad and PS_ReadNotepad.
# - image is 256*288 pixels. stored in "buffers". there are two 512 bytes buffers.
# -- image transfer: module sends upper 4 bits of each pixel (16 grey-degrees)
# - CharBuffer1, CharBuffer2 for templates
#
