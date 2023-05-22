# !/usr/bin/python3
import numpy as np
import matplotlib.pyplot as plt

# parameters to modify
filename="ping_test001.txt"
label='ping'
xlabel = 'Ping Time'
ylabel = 'CDF'
title='Simple plot'
fig_name='test.png'


t = np.loadtxt(filename, delimiter=" ", dtype="float")
print(t)
data = t
data_sorted = np.sort(data)
p = 1. * np.arange(len(data))/(len(data)-1)

plt.plot(data_sorted, p, label=label)  # Plot some data on the (implicit) axes.
plt.xlabel(xlabel)
plt.ylabel(ylabel)
plt.title(title)
plt.legend()
plt.savefig(fig_name)
plt.show()
