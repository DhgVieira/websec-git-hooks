import base64
import json
import os
import uuid
import subprocess
import time
import zlib

UTF_8 = 'utf-8'


def is_check_skipped() -> bool:
    """
    Returns the value of the environmental variable skip_credentials_check
    """
    try:
        return os.environ["skip_credentials_check"] == "true"
    except KeyError:
        return False


def exec_command(cmd) -> str:
    """
    Executes a command and returns the output
    :param cmd The command to be executed
    """
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = proc.communicate()
    return stdout


def generate_uuid():
    """
    Generates a uuid v4
    """
    return uuid.uuid4()


def measure_time(send_time):
    """
        decorator (@measure_time) that measures the time it takes to execute the function where it is used
    """
    def measure_time_decorator(function):
        def function_measured(*args, **kwargs):
            """
            function to be measured
            :param args Variable arguments that the function to measure receives (tuple)
            :param kwargs Variable arguments that the function to measure receives (dict) They allow us to give a name to each input argument, being able to access them within the function through a dictionary.
            """
            start_process_time_seg = time.time()
            response_function_measured = function(*args, **kwargs)
            end_process_time_seg = time.time()
            total_time_seg = end_process_time_seg - start_process_time_seg
            total_process_time_ms = round(total_time_seg * 1000, 4)
            send_time(total_process_time_ms)
            return response_function_measured

        return function_measured

    return measure_time_decorator


def zip_data(data) -> bytes:
    """
        data this transform in bytes and zip use algorithm deflation (lossless compression algorithm)
    """
    data_bytes = str(json.dumps(data)).encode(UTF_8)
    compression_level = zlib.Z_BEST_COMPRESSION
    compressed_data = zlib.compress(data_bytes, level=compression_level)
    return compressed_data


def encoding_base64_data(data) -> bytes:
    """
        data encoded to base64 and decoded to unicode, in order to guarantee that the data is not corrupted and can be transformed on the other side
    """
    encoding_data = base64.b64encode(data).decode(UTF_8)
    return encoding_data
