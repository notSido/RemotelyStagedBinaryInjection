# Binary injection demo

## Introduction
the abomination you are looking at here is my first project in the realm of malware development, and the first C program that i have ever written without having a guide up on my other monitor. not saying i did not consult external sources, but i tried my best to not just "code along".

This program will serve as a base for other programs that i want to write, and the more techniques i learn, the more this program will change. for example: the next planned evolution for this *thing* is rewriting it to work with the ntapi instead of the win32 api. naturally other minor improvements will be made along the way as i learn more about C and low level programming in general.

if anyone actually decides to read this at some point, i **really** want to hear your feedback. flame me even, i want to know where i can improve and what i need to focus on learning next. 

ps. when i rewrite this thing to use the NTAPI, i will include my header file so others can use it, since i couldn't find any online (there is a chance that i just didn't look hard enough though).

## What is this thing?
this program injects a binary payload into a given process, identified by its (you guessed it) Process ID which needs to be passed to the program as an argument. quick rundown of how the program functions:

1. open a handle to the provided process using the PID (with all_access, i know it's a huge red flag but i thought it was good enough for a demonstration)
2. open a handle to wininet
3. open a handle with the URL of the specified payload
4. allocate memory for a temporary buffer (1024 bytes)
5. read the payload
    1. save read data to the temporary buffer (max of 1024 bytes)
    2. record the amount of bytes read
6. set size value for the final buffer
7. allocate memory for the final buffer, the amount of memory allocated to the final buffer is determined by the amount of bytes read by InternetReadFile()
8. write contents of the temporary buffer to the final buffer
9. copy the final payload buffer to a new variable *
10. copy the size of the payload buffer to a new variable as well *
    1. clean up
11. allocate memory in the memory space of the specified process
12. write the payload to the previously allocated memory
13. create a thread to run the payload
14. wait until created thread completes execution
15. clean up and exit

# Info
to be able to compile this you will need to add wininet.lib to your build configuration:

1. open your solution's properties
2. go to Linker -> input
3. append this ```;wininet.lib``` to the end of the ```Additional Dependencies``` field

this lets the application build properly, though who knows maybe it's included in the .sln file and this works as long as you clone this repo. Visual Studio is weird.


#### Contact
*discord: notsido*\
*telegram: notsido*

you can shit on my shitty programming skills here
