import json
import make_header

supported_platforms_jsonfile = "supported_platforms.json"
prebuilt_dir = "stable_headers/"

if __name__ == "__main__":
    with open(supported_platforms_jsonfile, "r") as json_file:
        platform_info_json = json.load(json_file)
        for platform in platform_info_json.keys():
            print("Building", platform)
            make_header.build(platform, prebuilt_dir)