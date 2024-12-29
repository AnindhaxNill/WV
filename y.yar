rule Detect_Hello_World_Assembly
{
    meta:
        description = "Detects assembly code that outputs 'Hello, World!'"
        author = "Your Name"
        date = "2024-11-24"
        version = "1.0"

    strings:
        // Detect ASCII "Hello, World!"
        $hello_world_string = "Hello, World!"
        
        // Detect typical Linux x86 sys_write syscall instructions
        $syscall_write = { B8 04 00 00 00 BB 01 00 00 00 B9 ?? ?? ?? ?? BA ?? ?? ?? ?? CD 80 }
        
        // Detect exit syscall
        $syscall_exit = { B8 01 00 00 00 BB 00 00 00 00 CD 80 }

    condition:
        $hello_world_string or ($syscall_write and $syscall_exit)
}



rule Detect_Print_Hello_World
{
    meta:
        description = "Detects the Python statement: print('Hello World') in any file"
        author = "Your Name"
        date = "2024-11-24"
        version = "1.0"

    strings:
        // Detect "print('Hello, World!)" in ASCII
        $hello_world_python = "print(\"Hello, World!\")"

    condition:
        // Match if the string is found in the file
        $hello_world_python
}


rule Detect_Hello_World
{
    meta:
        description = "Detects the string 'Hello World' in any file, including EXEs"
        author = "Your Name"
        date = "2024-11-24"

    strings:
        $hello_world_ascii = "Hello World"
        $hello_world_utf16 = "Hello World" wide
        $hello_world_base64 = "SGVsbG8gV29ybGQ="
        $hello_hex = {48 65 6c 6c 6f 20 57 6f 72 6c 64}

    condition:
        $hello_world_ascii or $hello_world_utf16 or $hello_world_base64 or $hello_hex 
}