import json
import sys

# import bencodepy - available if you need it!
# import requests - available if you need it!
    
# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def decode_bencode(bencoded_value):
    if chr(bencoded_value[0]).isdigit():
        first_colon_index = bencoded_value.find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        strlen = int(bencoded_value[:first_colon_index])
        return bencoded_value[first_colon_index+1:first_colon_index+1+strlen], bencoded_value[first_colon_index+1+strlen:]
    elif bencoded_value[0:1] == b"i":
        idx_of_e = bencoded_value.find(b"e")
        if idx_of_e == -1:
            raise ValueError("Invalid encoded value")
        return int(bencoded_value[1:idx_of_e]), bencoded_value[idx_of_e+1:]
    elif bencoded_value[0:1] == b"l":
        blist = []
        bencoded_value = bencoded_value[1:]
        while bencoded_value[0:1] != b"e":
            item, bencoded_value = decode_bencode(bencoded_value)
            blist.append(item)
        return blist, bencoded_value[1:]
    elif bencoded_value[0:1] == b"d":
        bdict = {}
        bencoded_value = bencoded_value[1:]
        while bencoded_value[0:1] != b"e":
            key, bencoded_value = decode_bencode(bencoded_value)
            print(key,bencoded_value)
            if not isinstance(key,bytes):
                raise ValueError("Key must be of type string")
            value, bencoded_value = decode_bencode(bencoded_value)
            bdict[key] = value
        return bdict, bencoded_value[1:]
    else:
        raise NotImplementedError("Only strings, integers and lists are supported at the moment")


def main():
    command = sys.argv[1]

    # You can use print statements as follows for debugging, they'll be visible when running tests.
    #print("Logs from your program will appear here!")

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # Let's convert them to strings for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()

            raise TypeError(f"Type not serializable: {type(data)}")

        # Uncomment this block to pass the first stage
        decoded, _ = decode_bencode(bencoded_value)
        print(json.dumps(decoded, default=bytes_to_str))
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
