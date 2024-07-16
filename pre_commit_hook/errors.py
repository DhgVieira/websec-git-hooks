DOCU_MSG = "Check the FAQ section of the official docs first, maybe this issue is solved there: https://furydocs.io/sast-precommit//guide/#/lang-en/FAQs."

class RequestError(Exception):
    """
    Exception raised when there is a request error.
    :param msg Explanation of the error
    :param status_code Request status code
    :param url Request URL
    :param text Request response text
    :param client_msg Error client msg
    """
    def __init__(self, msg: str, status_code: int, url: str, text: str, client_msg: str):
        super().__init__(msg)
        self.status_code = status_code
        self.url = url
        self.response_text = text
        self.client_msg = client_msg

class ClientError(RequestError):
    """
    Exception raised when there is a client error while doing an API call.
    :param status_code Request status code
    :param url Request URL
    :param text Request response text
    """
    def __init__(self, status_code: int, url: str, text: str):
        super().__init__("Client error response when making request", status_code, url, text, 
            f"There was an error trying to connect with external resources (status code: {status_code}).\n{DOCU_MSG}\nIf not, please create a ticket on Fury Support Precommit > Websec Hook > Fails.")

class ServerError(RequestError):
    """
    Exception raised when there is a server error while doing an API call.
    :param status_code Request status code
    :param url Request URL
    :param text Request response text
    """
    def __init__(self, status_code: int, url: str, text: str):
        super().__init__("Server error response when making request", status_code, url, text, 
            f"There was an error trying to connect with external resources.\n{DOCU_MSG}\nTry again and create a ticket on Fury Support Precommit > Websec Hook > Fails if the error persists.")

class UnexpectedError(Exception):
    """
    Unexpected exception raised.
    :param message Explanation of the error
    """
    def __init__(self, message: str):
        super().__init__(message)

class DiffError(Exception):
    """
    Exception raised when there is an error getting the diff.
    :param ex Exception raised
    """
    def __init__(self, ex: Exception):
        super().__init__(f"Error getting diff: {ex}")

class RepoError(Exception):
    """
    Invalid repository.
    :param message Explanation of the error
    """
    def __init__(self, ex: Exception):
        super().__init__(f"Repository not found: {ex}")

class UserError(Exception):
    """
    Invalid user.
    :param message Explanation of the error
    """
    def __init__(self):
        super().__init__("No user found")

class GitDirectoryError(Exception):
    """
    An exception was raised when trying to get git directory
    :param message Explanation of the error
    """
    def __init__(self, ex: Exception):
        super().__init__(f"error getting git directory: {ex}")