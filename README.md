# windows_rootk1t
Some sample code about windows' kmd rootkit implement. 

Tested on Windows 7 32bit  version6.1(Internal version7601: Service Pack 1)

- HideProc- hook SSDT隐藏进程
  - 关于这个有个问题，查到的大多数博客均称：在ntdll中查找的导出表的ZwQuerySystemInformation算得的是ZwQuerySystemInformation的索引，所以hook的是ssdt的ZwQuerySystemInformation项；
  - 其实经过实际调试，在内核中经过查看SSDT对应项可以看到，实际上算得的索引项对应的地址其实是NtQuerySystemInformation，这大概是因为ZwQuerySystemInformation和NtQuerySystemInformation在ntdll.dll中的RVA是相同的，为啥相同我不太清楚，不过内核中最后NtQuerySystemInformation依然会去调用ZwQuerySystemInformation
  - 我看到几乎所有的博客都是写的hook ZwQuerySystemInformation，郁闷
- HideDriver- 修改DriverObject对象的DRIVER_SECTION隐藏驱动自身
- [Driver loader for bypassing Windows x64 Driver Signature Enforcement](https://github.com/hfiref0x/TDL)

