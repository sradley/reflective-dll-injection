                                                                 Stephen Radley
                                                                 September 2020

                           Reflective DLL Injection
                                Version 0.1.0

Copyright Notice

    Copyright (c) Stephen Radley (2020). All Rights Reserved.

Repository

    https://github.com/sradley/reflective-dll-injection

Warning
    
    The purpose of this repository is for educational purposes only. I strongly
    advise only running this code on machines that you personally own.
    
    I do not endorse the use of this code for any reason other than education.
    Nor do I take any responsibility in the event that it is used for malicious
    or illegal purposes.

Overview

    This project is an educational proof-of-concept focused on developing a
    working implementation of reflective dll injection utilising Windows'
    portable executable api.

Usage

    Taking a look at `src/main.c`, you can see that the bytes of an executable
    file are read in, before being initialised as a portable executable. The
    portable executable's entry point is then called, before the PE itself, and
    the buffer containing the executable are freed from memory.

    ```
    ...

    int main()
    {
	    // read in bytes of file
	    char* buf = read_bytes("./resources/helloworld.exe");
	    if (!buf)
		    return 1;

	    // Create portable executable
	    int error_code = 0;
	    exe_handle_t handle = exe_handle_new((void*)buf, 1, &error_code);
	
	    // Call the entry-point of the portable executable.
	    exe_handle_main(handle);

	    // Free portable executable and bytes of physical executable from
        // memory.
	    exe_handle_free(handle);
	    free(buf);
    }

    ...
    ```