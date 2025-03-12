rule Detect_Hello_World
{
    meta:
        description = "Detects variations of the string 'Hello World' in any file, including EXEs"
        author = "Your Name"
        date = "2024-11-24"

    strings:
        $hello_world_ascii = "Hello World"
        $hello_world_utf16 = "Hello World" wide
        $hello_world_base64 = "SGVsbG8gV29ybGQ="
        $hello_hex = {48 65 6c 6c 6f 20 57 6f 72 6c 64}
        $hello_regex = /H[e3]llo[\s]*World/i

    condition:
        $hello_world_ascii or
        $hello_world_utf16 or
        $hello_world_base64 or
        $hello_hex or
        $hello_regex
}