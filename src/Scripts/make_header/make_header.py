import sys
import json
import os
import re
import math
import shutil


supported_platforms_jsonfile = "supported_platforms.json"
root_path = "../../../"
st_src_dir_path = "../../Swarmtalk/"
driver_dir_path = ""
platform_info_json = []
swarmtalk_src_list = []
platform_driver_src_list = []
included_list = []
include_formatter = "#include \"{}.h\""


def str_comment(content):
    length = 50
    star_count = 8
    space_count_head = math.ceil((length - star_count * 2 - len(content)) / 2)
    space_count_tail = math.floor((length - star_count * 2 - len(content)) / 2)
    buff = "\n\n"
    buff = buff + "/" + "*" * length + "/\n"
    buff = buff + "/" + "*" * star_count + " " * \
        (length - star_count * 2) + "*" * star_count + "/\n"
    buff = buff + "/" + "*" * star_count + " " * space_count_head + \
        content + " " * space_count_tail + "*" * star_count + "/\n"
    buff = buff + "/" + "*" * star_count + " " * \
        (length - star_count * 2) + "*" * star_count + "/\n"
    buff = buff + "/" + "*" * length + "/\n\n"
    return buff


def include_header(in_file_dir, in_file_name):
    global swarmtalk_src_list
    global platform_driver_src_list
    global included_list
    header_buffer = ""
    out_buffer = str_comment("Start of " + in_file_name)
    in_file_dir = in_file_dir + "/"

    try:
        in_file = open(in_file_dir + in_file_name, "r")
    except IOError:
        # file not exist
        print("File [" + in_file_dir + in_file_name + "] does not exist")
        return out_buffer

    for line in in_file:
        replace = False
        skip = False
        replace_dir = ""
        replace_file = ""
        include_file = re.findall("#include \"(.*)\"", line)
        if include_file:
            include_file = os.path.abspath(
                in_file_dir + include_file[0]).rsplit(".", 1)[0]
            # print(include_file)
            if include_file not in included_list:
                if include_file in swarmtalk_src_list:
                    global st_src_dir_path
                    replace = True
                    included_list = included_list + [include_file]
                    replace_dir = st_src_dir_path
                    replace_file = include_file.split("/")[-1]
                elif include_file in platform_driver_src_list:
                    global driver_dir_path
                    replace = True
                    included_list = included_list + [include_file]
                    replace_dir = driver_dir_path
                    replace_file = include_file.split("/")[-1]
            else:
                skip = True
        if skip:
            out_buffer = out_buffer
        elif replace:
            print("Trying to include header " + replace_dir + "/" + replace_file + ".h")
            header_buffer = header_buffer + \
                include_header(replace_dir, replace_file + ".h")
        else:
            out_buffer = out_buffer + line
    in_file.close()
    out_buffer = out_buffer + str_comment("End of " + in_file_name)
    out_buffer = header_buffer + out_buffer
    return out_buffer


def include_src():
    global swarmtalk_src_list
    global platform_driver_src_list
    out_buffer = ""

    for file in included_list:
        file_name = file + ".cpp"
        try:
            in_file = open(file_name, "r")
        except IOError:
            # file not exist
            print("File [" + file_name + "] does not exist")
            continue

        print("Trying to include src " + file_name)
        out_buffer = out_buffer + \
            str_comment("Start of " + file_name.rsplit("/", 1)[1])

        # get rid of the lines that includes swarmtalk headers
        for line in in_file:
            skip = False
            include_file = re.findall("#include \"(.*)\"", line)
            if include_file:
                include_file = os.path.abspath(file_name.rsplit(
                    "/", 1)[0] + "/" + include_file[0]).rsplit(".", 1)[0]
                if include_file in (swarmtalk_src_list + platform_driver_src_list):
                    skip = True
            if not skip:
                out_buffer = out_buffer + line

        out_buffer = out_buffer + \
            str_comment("End of " + file_name.rsplit("/", 1)[1])
        in_file.close()

    return out_buffer


def build(platform_name, build_dir_path):
    # load platform info
    global platform_info_json
    with open(supported_platforms_jsonfile, "r") as json_file:
        platform_info_json = json.load(json_file)

    if platform_name not in platform_info_json.keys():
        sys.exit("Unrecognized platform " + platform_name)

    # find entry driver file
    global driver_dir_path
    platform = platform_info_json[platform_name]
    driver_dir_path = platform["driver_dir"]

    # find files in platform driver src
    global platform_driver_src_list
    for _, _, files in os.walk(platform["driver_dir"]):
        for filename in files:
            filename_without_tail = filename.rsplit(".", 1)[0]
            abs_path_to_file = os.path.abspath(
                platform["driver_dir"] + "/" + filename_without_tail)
            if abs_path_to_file not in platform_driver_src_list:
                platform_driver_src_list = platform_driver_src_list + \
                    [abs_path_to_file]

    print("Collected src files in platform driver directory: ")
    for f in platform_driver_src_list:
        print(f)
    print()

    # find files in swarmtalk src
    global swarmtalk_src_list
    st_path = root_path + "src/Swarmtalk/"
    for _, _, files in os.walk(st_path):
        for filename in files:
            filename_without_tail = filename.rsplit(".", 1)[0]
            abs_path_to_file = os.path.abspath(
                st_path + "/" + filename_without_tail)
            if abs_path_to_file not in swarmtalk_src_list:
                swarmtalk_src_list = swarmtalk_src_list + \
                    [abs_path_to_file]

    print("Collected src files in SwarmTalk directory: ")
    for f in swarmtalk_src_list:
        print(f)
    print()

    # create destination folder if not exist
    dest_path = root_path + build_dir_path + platform_name
    if not os.path.exists(dest_path):
        os.makedirs(dest_path)

    # build the output code in memory buffer recursively
    # first the headers
    output_buffer = include_header(
        driver_dir_path, platform["driver_file_name"])
    # next the cpp src
    output_buffer = output_buffer + include_src()

    # write the output code into dest file
    out_f = open(dest_path + "/" + platform["output_file_name"], "w")
    out_f.write(output_buffer)
    out_f.close()

    # copy the config file from driver to build 
    shutil.copyfile(driver_dir_path + "/config.h", dest_path + "/config.h")


if __name__ == "__main__":
    # parse input
    platform_name = ""
    build_dir_path = ""
    if len(sys.argv) == 2:
        platform_name = sys.argv[1]
        build_dir_path = "build/"
    elif len(sys.argv) == 3:
        platform_name = sys.argv[1]
        build_dir_path = sys.argv[2] + "/"
    else:
        sys.exit("Expecting 2 or 3 arguments instead of " + str(len(sys.argv) - 1))

    build(platform_name, build_dir_path)
