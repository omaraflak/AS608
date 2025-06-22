from dataclasses import dataclass
from enum import Enum
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
CMD_CAPTURE_FINGER = 0x01
CMD_GENERATE_FEATURES = 0x02
CMD_COMPARE_BUFFERS = 0x03
CMD_GENERATE_TEMPLATE = 0x05
CMD_STORE_TEMPLATE = 0x06
CMD_LOAD_TEMPLATE = 0x07
CMD_DOWNLOAD_BUFFER = 0x08
CMD_DELETE_TEMPLATES = 0xc
CMD_CLEAR_LIBRARY = 0xd
CMD_SET_SYSTEM_PARAMETERS = 0xe
CMD_SET_PASSWORD = 0x12
CMD_VERIFY_PASSWORD = 0x13
CMD_SET_MODULE_ADDRESS = 0x15
CMD_WRITE_NOTEPAD = 0x18
CMD_READ_NOTEPAD = 0x19
CMD_READ_SYSTEM_PARAMETERS = 0xf
CMD_READ_VALID_TEMPLATE_NUMBER = 0x1d
CMD_READ_INDEX_TABLE = 0x1f
CMD_TURN_LED_ON = 0x50
CMD_TURN_LED_OFF = 0x51
CMD_CAPTURE_FINGER_LED_OFF = 0x52
CMD_GET_ECHO = 0x53
CMD_DOWNLOAD_IMAGE_BUFFER = 0x0a

# Confirmation Codes
ACK_SUCCESS = 0x00
ACK_RECEIVE_ERROR = 0x01
ACK_NO_FINGER = 0x02
ACK_ENROLL_FAILED = 0x03
ACK_DISTORTED_IMAGE = 0x06
ACK_BLURRY_IMAGE = 0x07
ACK_NOT_MATCHED = 0x08
ACK_NOT_FOUND = 0x09
ACK_FAILED_TO_COMBINE_CHAR_FILES = 0x0A
ACK_PAGE_ID_OUT_OF_RANGE = 0x0B
ACK_INVALID_TEMPLATE = 0x0C
ACK_TEMPLATE_UPLOAD_FAILED = 0x0D
ACK_RECEIVE_PACKAGE_FAILED = 0x0E
ACK_IMAGE_UPLOAD_FAILED = 0x0F
ACK_DELETE_TEMPLATE_FAILED = 0x10
ACK_CLEAR_LIB_FAILED = 0x11
ACK_ERROR_COMMUNICATION_PORT = 0x13
ACK_FAILED_TO_GENERATE_CHAR_FILE = 0x15
ACK_ERROR_WRITING_FLASH = 0x18
ACK_INVALID_REGISTER = 0x1A
ACK_HANDSHAKE_SUCCESSFUL = 0x55

# System Paramaters Numbers
SYS_BAUD_SETTING = 0x04
SYS_SECURITY_LEVEL = 0x05
SYS_PACKAGE_LENGTH = 0x06

# Char Buffers
BUFFER_1 = 0x01
BUFFER_2 = 0x02


@dataclass
class SystemParameters:
    status_register: int
    system_identifier_code: int
    library_size: int
    security_level: int
    module_address: int
    data_packet_size: int
    baud_setting: int


class VerifyPassword(Enum):
    SUCCESS = 0
    ERROR_RECEIVING_PACKAGE = 1
    ERROR_COMMUNICATION_PORT = 2


class SetSystemParameter(Enum):
    SUCCESS = 0
    ERROR_RECEIVING_PACKAGE = 1
    ERROR_WRONG_REGISTER_NUMBER = 2


class CollectFingerImage(Enum):
    SUCCESS = 0
    ERROR_RECEIVING_PACKAGE = 1
    ERROR_CANNOT_DETECT_FINGER = 2
    ERROR_CANNOT_ENROLL_FINGER = 3


class ClearLibrary(Enum):
    SUCCESS = 0
    ERROR_RECEIVING_PACKAGE = 1
    ERROR_CLEARING_LIBRARY = 2


class DeleteTemplates(Enum):
    SUCCESS = 0
    ERROR_RECEIVING_PACKAGE = 1
    ERROR_DELETING_TEMPLATES = 2


class LoadTemplate(Enum):
    SUCCESS = 0
    ERROR_RECEIVING_PACKAGE = 1
    ERROR_READING_TEMPLATE = 2
    ERROR_PAGE_ID_OUT_OF_RANGE = 3


class StoreTemplate(Enum):
    SUCCESS = 0
    ERROR_RECEIVING_PACKAGE = 1
    ERROR_PAGE_ID_OUT_OF_RANGE = 2
    ERROR_WRITING_TEMPLATE = 3


class GenerateTemplate(Enum):
    SUCCESS = 0
    ERROR_RECEIVING_PACKAGE = 1
    ERROR_FAILED_TO_COMBINE_FILES = 2


class GenerateFeatures(Enum):
    SUCCESS = 0
    ERROR_RECEIVING_PACKAGE = 1
    ERROR_DISTORTED_IMAGE = 2
    ERROR_NOT_ENOUGH_FEATURES = 3
    ERROR_WEAK_IMAGE = 4


@dataclass
class Package:
    data: bytes
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
        data_packet_size: int = 128,
        timeout: float = 1
    ):
        self.port = port
        self.baudrate = baudrate
        self.module_address = module_address
        self.data_packet_size = data_packet_size
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

    def use_system_parameter(self, system_parameters: SystemParameters):
        self.baudrate = system_parameters.baud_setting * 9600
        self.data_packet_size = 2 ** (system_parameters.data_packet_size + 5)
        self.module_address = system_parameters.module_address

    def get_echo(self) -> bool:
        request = self._make_cmd_package(CMD_GET_ECHO.to_bytes())
        self._write(request)
        response = self._verify_ack(self.ser.read(12))
        return response and response.confirmation_code == ACK_HANDSHAKE_SUCCESSFUL

    def verify_password(self, password: int = 0) -> VerifyPassword | None:
        password_bytes = password.to_bytes(4)
        request = self._make_cmd_package(bytes(
            [CMD_VERIFY_PASSWORD, *password_bytes]))
        self._write(request)
        response = self._verify_ack(self.ser.read(12))
        if not response:
            return None

        if response.confirmation_code == ACK_SUCCESS:
            return VerifyPassword.SUCCESS

        if response.confirmation_code == ACK_RECEIVE_ERROR:
            return VerifyPassword.ERROR_RECEIVING_PACKAGE

        if response.confirmation_code == ACK_ERROR_COMMUNICATION_PORT:
            return VerifyPassword.ERROR_COMMUNICATION_PORT

        return None

    def set_password(self, password: int = 0) -> bool:
        password_bytes = password.to_bytes(4)
        request = self._make_cmd_package(bytes(
            [CMD_SET_PASSWORD, *password_bytes]))
        self._write(request)
        response = self._verify_ack(self.ser.read(12))
        return response and response.confirmation_code == ACK_SUCCESS

    def set_module_address(self, module_address: int = 0xffffffff) -> bool:
        module_address_bytes = module_address.to_bytes(4)
        request = self._make_cmd_package(bytes(
            [CMD_SET_MODULE_ADDRESS, *module_address_bytes]))
        self._write(request)
        response = self._verify_ack(self.ser.read(12))
        return response and response.confirmation_code == ACK_SUCCESS

    def _set_system_parameter(self, parameter_key: int, parameter_value: int) -> SetSystemParameter | None:
        request = self._make_cmd_package(bytes(
            [CMD_SET_SYSTEM_PARAMETERS, parameter_key, parameter_value]))
        self._write(request)
        response = self._verify_ack(self.ser.read(12))
        if not response:
            return None

        if response.confirmation_code == ACK_SUCCESS:
            return SetSystemParameter.SUCCESS

        if response.confirmation_code == ACK_RECEIVE_ERROR:
            return SetSystemParameter.ERROR_RECEIVING_PACKAGE

        if response.confirmation_code == ACK_INVALID_REGISTER:
            return SetSystemParameter.ERROR_WRONG_REGISTER_NUMBER

        return None

    def set_baud_setting(self, baud_setting: int = 6) -> SetSystemParameter | None:
        if not (1 <= baud_setting <= 12):
            logging.error(
                f"Baud rate setting is an integer in [0, 12]. The actual baud rate will be N*9600 bps. Received: {baud_setting}")
            return None

        return self._set_system_parameter(SYS_BAUD_SETTING, baud_setting)

    def set_security_level(self, security_level: int = 3) -> SetSystemParameter | None:
        if not (1 <= security_level <= 5):
            logging.error(
                f"Security level is an integer in [1, 5]. Received: {security_level}")
            return None

        return self._set_system_parameter(SYS_SECURITY_LEVEL, security_level)

    def set_data_package_length(self, package_length: int = 3) -> SetSystemParameter | None:
        if not (1 <= package_length <= 5):
            logging.error(
                f"Package length is one of 0,1,2,3 which correspond to 32,64,128,256 bytes. Received: {package_length}")
            return None

        return self._set_system_parameter(SYS_PACKAGE_LENGTH, package_length)

    def read_system_parameters(self) -> SystemParameters | None:
        request = self._make_cmd_package(CMD_READ_SYSTEM_PARAMETERS.to_bytes())
        self._write(request)

        response = self._verify_ack(self.ser.read(28))
        if not response:
            return None

        if response.confirmation_code != ACK_SUCCESS:
            logging.error(
                f"Expected confirmation code {ACK_SUCCESS}, but got {response.confirmation_code}. Data: {response.data.hex(' ')}")
            return None

        data = response.content[1:]
        return SystemParameters(
            status_register=int.from_bytes(data[0:2]),
            system_identifier_code=int.from_bytes(data[2:4]),
            library_size=int.from_bytes(data[4:6]),
            security_level=int.from_bytes(data[6:8]),
            module_address=int.from_bytes(data[8:12]),
            data_packet_size=int.from_bytes(data[12:14]),
            baud_setting=int.from_bytes(data[14:16]),
        )

    def read_template_index_table(self, index_page: int) -> list[bool] | None:
        if not (0 <= index_page <= 3):
            logging.error(
                f"Index page must be one of 0,1,2,3. Received: {index_page}")
            return None

        request = self._make_cmd_package(
            bytes([CMD_READ_INDEX_TABLE, index_page]))
        self._write(request)
        response = self._verify_ack(self.ser.read(44))

        if not response:
            return None

        if response.confirmation_code != ACK_SUCCESS:
            logging.error(
                f"Expected confirmation code {ACK_SUCCESS}, but got {response.confirmation_code}. Data: {response.data.hex(' ')}")
            return None

        index_table = [False] * 256

        p = 0
        for i, b in enumerate(response.content[1:]):
            for k in range(8):
                index_table[p] = (b & 1 << k) > 0
                p += 1

        return index_table

    def read_enrolled_fingers_count(self) -> int:
        request = self._make_cmd_package(
            CMD_READ_VALID_TEMPLATE_NUMBER.to_bytes())
        self._write(request)
        response = self._verify_ack(self.ser.read(14))
        if not response:
            return None

        if response.confirmation_code != ACK_SUCCESS:
            logging.error(
                f"Expected confirmation code {ACK_SUCCESS}, but got {response.confirmation_code}. Data: {response.data.hex(' ')}")
            return None

        return int.from_bytes(response.content[1:3])

    def capture_finger_image(self, led_on: bool = True) -> CollectFingerImage | None:
        pid = CMD_CAPTURE_FINGER if led_on else CMD_CAPTURE_FINGER_LED_OFF
        request = self._make_cmd_package(pid.to_bytes())
        self._write(request)
        response = self._verify_ack(self.ser.read(12))
        if not response:
            return None

        logging.debug(response.data.hex(' '))

        if response.confirmation_code == ACK_SUCCESS:
            return CollectFingerImage.SUCCESS

        if response.confirmation_code == ACK_RECEIVE_ERROR:
            return CollectFingerImage.ERROR_RECEIVING_PACKAGE

        if response.confirmation_code == ACK_NO_FINGER:
            return CollectFingerImage.ERROR_CANNOT_DETECT_FINGER

        if response.confirmation_code == ACK_ENROLL_FAILED:
            return CollectFingerImage.ERROR_CANNOT_ENROLL_FINGER

        return None

    def turn_led_on(self) -> bool:
        request = self._make_cmd_package(CMD_TURN_LED_ON.to_bytes())
        self._write(request)
        response = self._verify_ack(self.ser.read(12))
        return response and response.confirmation_code == ACK_SUCCESS

    def turn_led_off(self) -> bool:
        request = self._make_cmd_package(CMD_TURN_LED_OFF.to_bytes())
        self._write(request)
        response = self._verify_ack(self.ser.read(12))
        return response and response.confirmation_code == ACK_SUCCESS

    def turn_led(self, on: bool) -> bool:
        return self.turn_led_on() if on else self.turn_led_off()

    def download_image_buffer(self) -> bytes | None:
        request = self._make_cmd_package(CMD_DOWNLOAD_IMAGE_BUFFER.to_bytes())
        self._write(request)
        response = self._verify_ack(self.ser.read(12))
        if not response:
            return None

        if response.confirmation_code != ACK_SUCCESS:
            logging.error(
                f"Expected confirmation code {ACK_SUCCESS}, but got {response.confirmation_code}. Data: {response.data.hex(' ')}")
            return None

        return self._recv_and_verify_data()

    def generate_features(self, output_buffer_id: int) -> GenerateFeatures | None:
        if output_buffer_id not in [BUFFER_1, BUFFER_2]:
            logging.error(
                f"Buffer id must be one of [{BUFFER_1}, {BUFFER_2}]. Received: {output_buffer_id}")
            return None

        request = self._make_cmd_package(
            bytes([CMD_GENERATE_FEATURES, output_buffer_id]))
        self._write(request)
        response = self._verify_ack(self.ser.read(12))
        if not response:
            return None

        if response.confirmation_code == ACK_SUCCESS:
            return GenerateFeatures.SUCCESS

        if response.confirmation_code == ACK_RECEIVE_ERROR:
            return GenerateFeatures.ERROR_RECEIVING_PACKAGE

        if response.confirmation_code == ACK_DISTORTED_IMAGE:
            return GenerateFeatures.ERROR_DISTORTED_IMAGE

        if response.confirmation_code == ACK_BLURRY_IMAGE:
            return GenerateFeatures.ERROR_NOT_ENOUGH_FEATURES

        if response.confirmation_code == ACK_FAILED_TO_GENERATE_CHAR_FILE:
            return GenerateFeatures.ERROR_WEAK_IMAGE

        return None

    def generate_template(self) -> GenerateTemplate | None:
        request = self._make_cmd_package(CMD_GENERATE_TEMPLATE.to_bytes())
        self._write(request)
        response = self._verify_ack(self.ser.read(12))
        if not response:
            return None

        if response.confirmation_code == ACK_SUCCESS:
            return GenerateTemplate.SUCCESS

        if response.confirmation_code == ACK_RECEIVE_ERROR:
            return GenerateTemplate.ERROR_RECEIVING_PACKAGE

        if response.confirmation_code == ACK_FAILED_TO_COMBINE_CHAR_FILES:
            return GenerateTemplate.ERROR_FAILED_TO_COMBINE_FILES

        return None

    def download_buffer(self, buffer_id: int) -> bytes | None:
        if buffer_id not in [BUFFER_1, BUFFER_2]:
            logging.error(
                f"Buffer id must be one of [{BUFFER_1}, {BUFFER_2}]. Received: {buffer_id}")
            return None

        request = self._make_cmd_package(
            bytes([CMD_DOWNLOAD_BUFFER, buffer_id]))
        self._write(request)

        response = self._verify_ack(self.ser.read(12))

        if not response:
            return None

        if response.confirmation_code != ACK_SUCCESS:
            logging.error(f"Could not download buffer {buffer_id} content")
            return None

        return self._recv_and_verify_data()

    def store_template(self, output_page_id: int, input_buffer_id: int) -> StoreTemplate | None:
        if input_buffer_id not in [BUFFER_1, BUFFER_2]:
            logging.error(
                f"Buffer id must be one of [{BUFFER_1}, {BUFFER_2}]. Received: {input_buffer_id}")
            return None

        request = self._make_cmd_package(
            bytes([CMD_STORE_TEMPLATE, input_buffer_id, *output_page_id.to_bytes(2)]))
        self._write(request)
        response = self._verify_ack(self.ser.read(12))
        if not response:
            return None

        if response.confirmation_code == ACK_SUCCESS:
            return StoreTemplate.SUCCESS

        if response.confirmation_code == ACK_RECEIVE_ERROR:
            return StoreTemplate.ERROR_RECEIVING_PACKAGE

        if response.confirmation_code == ACK_PAGE_ID_OUT_OF_RANGE:
            return StoreTemplate.ERROR_PAGE_ID_OUT_OF_RANGE

        if response.confirmation_code == ACK_ERROR_WRITING_FLASH:
            return StoreTemplate.ERROR_WRITING_TEMPLATE

        return None

    def load_template(self, input_page_id: int, output_buffer_id: int) -> LoadTemplate | None:
        if output_buffer_id not in [BUFFER_1, BUFFER_2]:
            logging.error(
                f"Buffer id must be one of [{BUFFER_1}, {BUFFER_2}]. Received: {output_buffer_id}")
            return None

        request = self._make_cmd_package(
            bytes([CMD_LOAD_TEMPLATE, output_buffer_id, *input_page_id.to_bytes(2)]))
        self._write(request)
        response = self._verify_ack(self.ser.read(12))
        if not response:
            return None

        if response.confirmation_code == ACK_SUCCESS:
            return LoadTemplate.SUCCESS

        if response.confirmation_code == ACK_RECEIVE_ERROR:
            return LoadTemplate.ERROR_RECEIVING_PACKAGE

        if response.confirmation_code == ACK_INVALID_TEMPLATE:
            return LoadTemplate.ERROR_READING_TEMPLATE

        if response.confirmation_code == ACK_PAGE_ID_OUT_OF_RANGE:
            return LoadTemplate.ERROR_PAGE_ID_OUT_OF_RANGE

        return None

    def delete_templates(self, page_id: int, template_count: int) -> DeleteTemplates | None:
        request = self._make_cmd_package(
            bytes([CMD_DELETE_TEMPLATES, *page_id.to_bytes(2), *template_count.to_bytes(2)]))
        self._write(request)
        response = self._verify_ack(self.ser.read(12))
        if not response:
            return None

        if response.confirmation_code == ACK_SUCCESS:
            return DeleteTemplates.SUCCESS

        if response.confirmation_code == ACK_RECEIVE_ERROR:
            return DeleteTemplates.ERROR_RECEIVING_PACKAGE

        if response.confirmation_code == ACK_DELETE_TEMPLATE_FAILED:
            return DeleteTemplates.ERROR_DELETING_TEMPLATES

        return None

    def clear_library(self) -> ClearLibrary | None:
        request = self._make_cmd_package(CMD_CLEAR_LIBRARY.to_bytes())
        self._write(request)
        response = self._verify_ack(self.ser.read(12))
        if not response:
            return None

        if response.confirmation_code == ACK_SUCCESS:
            return ClearLibrary.SUCCESS

        if response.confirmation_code == ACK_RECEIVE_ERROR:
            return ClearLibrary.ERROR_RECEIVING_PACKAGE

        if response.confirmation_code == ACK_CLEAR_LIB_FAILED:
            return ClearLibrary.ERROR_CLEARING_LIBRARY

        return None

    def compare_buffers(self) -> int | None:
        request = self._make_cmd_package(CMD_COMPARE_BUFFERS.to_bytes())
        self._write(request)
        response = self._verify_ack(self.ser.read(14))
        if not response:
            return None

        score = int.from_bytes(response.content[1:3])

        if response.confirmation_code in [ACK_SUCCESS, ACK_NOT_MATCHED]:
            return score

        if response.confirmation_code == ACK_RECEIVE_ERROR:
            logging.error("Error while receiving package.")

        return None

    def write_notepad(self, page: int, data: bytes) -> bool:
        if not (0 <= page <= 15):
            logging.error(
                f"Page must be in [0, 15]. Received: {page}")
            return None

        if len(data) > 32:
            logging.error(
                f"Data must be at most 32 bytes. Received data of length {len(data)} bytes.")

        if len(data) < 32:
            logging.warning(
                f"Data will be written over 32 bytes. Appended 0x0 bytes to reach 32 bytes.")
            data += bytes(32 - len(data))

        request = self._make_cmd_package(
            bytes([CMD_WRITE_NOTEPAD, page, *data]))
        self._write(request)
        response = self._verify_ack(self.ser.read(12))
        return response and response.confirmation_code == ACK_SUCCESS

    def read_notepad(self, page: int) -> bytes | None:
        if not (0 <= page <= 15):
            logging.error(
                f"Page must be in [0, 15]. Received: {page}")
            return None

        request = self._make_cmd_package(
            bytes([CMD_READ_NOTEPAD, page]))
        self._write(request)

        response = self._verify_ack(self.ser.read(44))

        if not response:
            return None

        if response.confirmation_code != ACK_SUCCESS:
            logging.error(f"Could not read page {page} of notepad")
            return None

        return response.content[1:]

    def _recv_and_verify_data(self) -> bytes | None:
        data = bytes()
        while True:
            response = self._verify_data(
                self.ser.read(11 + self.data_packet_size))

            if not response:
                return None

            data += response.content

            if response.pid == PID_EOD:
                return data

    def _write(self, data: bytes) -> bool:
        count = self.ser.write(data)
        if count == len(data):
            return True

        logging.error(
            f"Expected to write {len(data)} bytes, but wrote {count}")
        return False

    def _make_cmd_package(self, content: bytes) -> bytes:
        return self._make_package(PID_CMD, content)

    def _make_data_package(self, content: bytes) -> bytes:
        return self._make_package(PID_DATA, content)

    def _make_package(self, pid: int, content: bytes) -> bytes:
        header = HEADER + self.module_address.to_bytes(4)
        length = len(content) + 2
        body = bytes([pid]) + length.to_bytes(2) + content
        checksum = self._compute_checksum(pid, length, content)
        package = header + body + checksum
        logging.debug(f"Built package: {package.hex(sep=' ')}")
        return package

    def _verify_ack(self, data: bytes | None) -> Package | None:
        return self._verify_package(PID_ACK, data)

    def _verify_data(self, data: bytes | None) -> Package | None:
        return self._verify_package(None, data)

    def _verify_package(self, pid: int | None, data: bytes | None) -> Package | None:
        if not data:
            return None

        package = FingerprintModule._parse_package(data)

        if not package:
            return None

        if package.module_address != self.module_address:
            logging.error(
                f"Expected header {self.module_address} but got {package.module_address}. Package: {data.hex(' ')}")
            return None

        if pid is not None and package.pid != pid:
            logging.error(
                f"Expected pid {pid} but got {package.pid}. Package: {data.hex(' ')}")
            return None

        return package

    @staticmethod
    def _parse_package(data: bytes) -> Package | None:
        package = Package(
            data=data,
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
