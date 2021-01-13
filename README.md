
# LinuxProfiler
This project is an initial attempt to implement a Linux Profiler module that can keep track of task PIDs provided by user to the profiler. The Profiler module is capable of tracking number of times the task is scheduled and the amount of time it spends on CPU. The implementation is user-friendly and lightweight, as only the task PIDs provided by the user, to the module, are tracked and stored in memory. The user inputs and profiler statistics data are managed using proc filesystem.  

## Directory Structure
```
LinuxProfiler
    \_____ Makefile
    \_____ README.md
    \_____ procModule.c
```

## Compilation and Module Load/Unload
Compile the Linux module using following command:  
```
make all
```
Above command will generate a kernel module file with extension ```.ko``` that can used to load module.  

To load the module, use following command:  
```
sudo insmod procModule.ko
```

To unload the module, use following command:  
```
sudo rmmod procModule
```

Any debug prints that are used inside module (using ```printk```) can be checked using following command:
```
dmesg
```

## Execution
When this module is loaded, it creates a new file in ```/proc``` directory with name ```profiler```. This file is the interface between user and the kernel module. User can write the PID of the task that needs to be monitored to this file.  

To write the PID of process to the file, use following command:  
```
echo 1152 > /proc/profiler       /* here 1152 is just an example PID of a task in Linux. */
```
  
When the PID of task is written to the ```/proc/profiler```, the module starts monitoring the task with the given PID. The module collects various information such as number of times the scheduler has chosen this task to schedule and the amount of time the task spends on CPU.  

After giving the PID to module, the profiling data can be printed on terminal, using following command:
```
cat /proc/profiler
```

## Future Work
1. Add functionality to remove a given task from profiling list.  
2. Add functionality to enhance profiling information such as adding kernel stack trace information for the task.
