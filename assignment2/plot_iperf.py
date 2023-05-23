# !/usr/bin/python3
import numpy as np
import matplotlib.pyplot as plt

# parameters to modify
filename="Iperf_bidir.txt"
label='label'
xlabel = 'time/s'
ylabel = 'bandwidth(Mbits per second)'
title='Bandwidth Bidirectional Plot'
fig_name='test.png'


bitrate = np.loadtxt(filename, dtype="float")
print(bitrate)
bitrate_forward = bitrate[: : 2]
bitrate_backward = bitrate[1: : 2]


plt.plot( bitrate_backward,label= 'backward_bandwidth')  
# Plot some data on the (implicit) axes.

plt.plot( bitrate_forward,label = 'forward_bandwidth')

plt.xlabel(xlabel)
plt.ylabel(ylabel)
plt.title(title)
plt.legend()
plt.savefig(fig_name)
plt.show()
