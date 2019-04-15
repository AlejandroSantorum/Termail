
# Auxiliary function to allow users send messages with spaces through terminal input
def prepare_msg(array_str):
    msg = ""
    i = 3
    length = len(array_str)
    while i<length:
        msg += array_str[i]
        if i != length:
            msg += " "
        i += 1
    return msg
