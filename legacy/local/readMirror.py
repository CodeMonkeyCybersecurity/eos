#!/usr/bin/env python3

def main():
    file_path = '/etc/apt/sources.list.d/ubuntu.sources'
    try:
        with open(file_path, 'r') as file:
            contents = file.read()
            print(contents)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")

if __name__ == '__main__':
    main()
