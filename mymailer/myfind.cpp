#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <list>
#include <getopt.h>
#include <assert.h>
#include <algorithm>

using namespace std;
namespace fs = std::filesystem;


// Splits to strings into their chairs and compares them while always lowering the case
bool caseInsensitiveEquals(string b, string a)
{
    return equal(a.begin(), 
                    a.end(),
                    b.begin(), 
                    b.end(),
                    [](char a, char b) 
                    {
                        return tolower(a) == tolower(b);
                    });
}

// Since we need it in two places, this logic has its own method
bool areStringsEqual(bool insensitive, string first, string second)
{
    if(insensitive)
    {
        // iequals is an case insensitive check for strings
        if(caseInsensitiveEquals(first, second))
        {
            return true;
        }
    }
    else 
    {
        // Here we use a regular compare, since we want the search to be case sensitive
        if(first.compare(second) == 0)
        {
            return true;
        }
    }
    return false;
}


std::string findFile(fs::path path, string filename, int indent, int max_indent, bool insensitive)
{
    //long way around
    std::string longway;

    // Collection to store child directories if they exist
    list<fs::path> child_directories;
    
    for(const fs::directory_entry& entry : fs::directory_iterator(path))
    {
        fs::path cpath = entry.path();

        if(fs::is_directory(cpath)) 
        {
            // If the current path is a directory, we add it to the child directories collection
            child_directories.push_back(cpath);
        }
        else
        {
            // If it is a file, we check if the name matches based on if the search is case sensitive or not and return it if true
            if(areStringsEqual(insensitive, filename, cpath.filename())) 
                return fs::absolute(cpath).string();;
        }
    }
    
    // Iterator for the child directories
    list<fs::path>::iterator it;
    for(it = child_directories.begin(); it != child_directories.end(); ++it)
    {   
        // Indent check if already max search depth has been reached
        if(indent < max_indent)
        {
            try
            {
                // Recursive call to scan the files in the child directories
                longway = findFile(*it, filename, indent + 1, max_indent, insensitive);
            }
            catch(const std::exception& e)
            {
                std::cerr << e.what() << '\n';
            }

            // Gets only the filename of the file without the path, since it is not wanted for comparison
            std::string lfilename = longway.substr(longway.find_last_of("/") + 1);

            if(areStringsEqual(insensitive, filename, lfilename)) 
                return longway;
        }
    }
    
    // If nothing was found, an empty string is returned
    return std::string();
}


// Will split all the provided filenames into their processess
int splitIntoProcesses(int numProcesses, char *argv[], int argdepth, int max_indent, bool insensetive)
{
    printf("<pid> : Searched <filename> in <directory> : <path to file> \n");

    for(int i = 0; i < numProcesses; i++)
    {
        // Create a process
        if(fork() == 0)
        {
            std::string outpath = std::string();
            

            // Starts the filesearch for the process
            try
            {
                fs::path path1(argv[argdepth]);
                std::string outpath = findFile(path1, argv[argdepth + i + 1], 0, max_indent, insensetive );
            }
            catch(const std::exception& e)
            {
                std::cerr << e.what() << '\n';
            }

            // If no file is found (returned string was empty), we print the information to the user
            if(outpath.empty())
            {
                printf("%d : Searched \"%s\" in \"%s\" : File not found \n",getpid(),argv[argdepth+i+1],argv[argdepth]);
                exit(-1);
            }

            // If a file was found, we print the path of the file to the user
            printf("%d : Searched \"%s\" in \"%s\" : %s \n",getpid(),argv[argdepth+i+1],argv[argdepth], outpath.c_str());
            exit(0);
        }
    }

    // Waits for all processes to finish
    for(int i = 0; i < numProcesses; i++) 
    {
        wait(NULL);
    }
}


int main(int argc, char *argv[])
{
    //reading the args
    if(argc >= 3 && argc <= 99)
    {
        int max_indent = 0;
        bool insensetive = false;
        int argdepth = 1;

        // getopt loop
        int c;
        while((c = getopt(argc, argv, "hRi:")) != EOF)
        {
            switch(c)
            {
                case '?': 
                case 'h':
                    // Shows help
                    std::cout << "Help: ./myfind [-R] [-i] searchpath filename1 [filename2] ...[filenameN]\n";
                    exit(0);
                case 'R':
                    // Enables recursive search
                    max_indent = 999;
                    argdepth += 1;
                    break;
                case 'i':
                    // Case insensitive search
                    insensetive = true;
                    argdepth += 1;
                    break;
                default:
                    // Assert for debugging
                    assert(0);
            }
        }

        // Check if enough arguments are given (minus the optional ones)
        if(argc - argdepth < 2)
        {
            std::cerr << "Not enough args";
            exit(1);
        }

        // If all requirements are met, we start the program
        splitIntoProcesses(argc-argdepth - 1, argv, argdepth, max_indent, insensetive);
    } 

    return 0;
}