#!/usr/bin/env python3

'''
Author: WO1 Tony Ruppert
Class: 24-002 WOBC
Py_Version: 3.8
Created_Date: 2May24
'''

'''
Create a class named Motorcycle with a speedup function, slowdown function, and a stop function.
Create the speedup and slowdown functions to accept a number and change the speed by that amount.
The stop function must set the speed back to 0.
Use the __str__() method to state the current speed.
'''

from sys import exit

class Motorcycle():
    ''' overall class to define motorcycle movement'''
    def __init__(self):
        self.current_speed = 0

    def speedup(self, speed_change):
        self.current_speed += speed_change
    
    def slowdown(self, speed_change):
        self.current_speed -= speed_change
        
    def stop_moving(self):
        self.current_speed = 0
        
    def __str__(self):
        return f'Your current speed is {self.current_speed}.'

harley = Motorcycle()
harley.speedup(40)
harley.slowdown(10)
yamaha = Motorcycle()
yamaha.speedup(60)
yamaha.stop_moving()
print(harley)
print(yamaha)
