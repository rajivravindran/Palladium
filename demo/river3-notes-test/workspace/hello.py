#!/usr/bin/env python3

def main():
    try:
        urllib.request.urlopen("https://www.pinterest.com/pin/786089310036643166/", timeout=5).read()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()