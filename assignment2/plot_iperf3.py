# !/usr/bin/python3
import numpy as np
import matplotlib.pyplot as plt

# parameters to modify
filename="Iperf3_Test1.txt"
label='label'
xlabel = 'time/s'
ylabel = 'bandwidth(Mbits per second)'
title='Bandwidth Plot'
fig_name='test.png'


bitrate = np.loadtxt(filename, dtype="float")
print(bitrate)


plt.plot( bitrate,label= 'Bitrate_iperf3_Test1')  
# Plot some data on the (implicit) axes.

plt.xlabel(xlabel)
plt.ylabel(ylabel)
plt.title(title)
plt.legend()
plt.savefig(fig_name)
plt.show()



