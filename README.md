[TOC]

我思考过debug_console的设计能否支持非入侵式地改动和新增内容，遗憾的是，截止至[skynet v1.6.0](https://github.com/cloudwu/skynet/releases/tag/v1.6.0)还做不到。
结果我新建了一个仓库维护这份代码。因为修改是基于[skynet v1.6.0](https://github.com/cloudwu/skynet/releases/tag/v1.6.0)，如果你不是这个版本，覆盖文件后注意检查skynet的接口变化


# 修改COMMAND.mem

修改前
```shel
mem
:01000004       65.64 Kb (snlua cmaster)
:01000005       70.77 Kb (snlua cslave)
:01000007       51.27 Kb (snlua datacenterd)       
:01000008       58.38 Kb (snlua service_mgr)       
:0100000a       290.04 Kb (snlua protoloader)      
:0100000b       64.67 Kb (snlua console)
:0100000c       85.10 Kb (snlua debug_console 8000)
:0100000d       53.62 Kb (snlua simpledb)
:0100000e       52.29 Kb (snlua watchdog)
:0100000f       60.24 Kb (snlua gate)
<CMD OK>
```
修改后
1. 按内存小到大排序
2. total_lua_mem是列出服务的lua内存总和
mem
 :01000007      51.27 Kb snlua datacenterd
 :0100000e      52.29 Kb snlua watchdog
 :0100000d      53.62 Kb snlua simpledb
 :01000008      58.38 Kb snlua service_mgr
 :0100000f      60.24 Kb snlua gate
 :0100000b      64.67 Kb snlua console
 :01000004      65.64 Kb snlua cmaster
 :01000005      70.77 Kb snlua cslave
 :0100000c      77.66 Kb snlua debug_console 8000
 :0100000a     290.04 Kb snlua protoloader
 total_lua_mem: 844.58 Kb

# 修改COMMAND.cmem

修改前
```shell
cmem
:01000001       1280
:01000002       182624
:01000003       45456
:01000004       68656
:01000005       99296
:01000006       144
:01000007       16208
:01000008       81088
:01000009       109648
:0100000a       19888
:0100000b       12672
:0100000c       144464
:0100000d       13328
:0100000e       15984
:0100000f       42320
:fffffffe       32
:ffffffff       10521008
block   6899
total   11374096
<CMD OK>
```
修改后
1. 内存小到大排序
2. 显示服务名称
3. 以kb单位显示内存

```shell
cmem
 :fffffffe            0.03 Kb   unknown
 :01000006            0.14 Kb   unknown
 :01000001            1.25 Kb   unknown
 :0100000b           12.38 Kb   snlua console
 :0100000d           13.02 Kb   snlua simpledb
 :0100000e           15.61 Kb   snlua watchdog
 :01000007           15.83 Kb   snlua datacenterd
 :0100000a           19.42 Kb   snlua protoloader
 :0100000f           41.33 Kb   snlua gate
 :01000003           44.39 Kb   unknown
 :01000004           67.05 Kb   snlua cmaster
 :01000008           79.19 Kb   snlua service_mgr
 :01000005           97.03 Kb   snlua cslave
 :01000009          107.08 Kb   unknown
 :0100000c          154.34 Kb   snlua debug_console 8000
 :01000002          178.34 Kb   unknown
 :ffffffff        10274.42 Kb   unknown
 total: 11121.12 Kb
 block: 6.85 Kb
```

# 修改COMMAND.stat

修改前
```shel
:01000004       cpu:0.014172    message:27      mqlen:0 task:1
:01000005       cpu:0.009033    message:29      mqlen:0 task:1
:01000007       cpu:0.004127    message:19      mqlen:0 task:0
:01000008       cpu:0.009153    message:21      mqlen:0 task:0
:0100000a       cpu:0.013299    message:19      mqlen:0 task:0
:0100000b       cpu:0.004354    message:20      mqlen:0 task:1
:0100000c       cpu:0.034882    message:70      mqlen:0 task:3
:0100000d       cpu:0.009319    message:19      mqlen:0 task:0
:0100000e       cpu:0.007863    message:22      mqlen:0 task:0
:0100000f       cpu:0.015734    message:22      mqlen:0 task:0
<CMD:stat OK>
```
修改后
1. 小到大排充，优先级 cpu > message > mqlen > task
2. 显示服务名称

```shel
stat
 :01000007 cpu:0.004379   message:3          mqlen:0     task:0     snlua datacenterd 
 :0100000d cpu:0.005379   message:3          mqlen:0     task:0     snlua simpledb
 :0100000e cpu:0.007225   message:6          mqlen:0     task:0     snlua watchdog
 :0100000b cpu:0.008725   message:4          mqlen:0     task:1     snlua console
 :0100000f cpu:0.009203   message:6          mqlen:0     task:0     snlua gate
 :01000008 cpu:0.009321   message:5          mqlen:0     task:0     snlua service_mgr
 :01000005 cpu:0.012152   message:13         mqlen:0     task:1     snlua cslave
 :01000004 cpu:0.01229    message:11         mqlen:0     task:1     snlua cmaster
 :0100000a cpu:0.012997   message:3          mqlen:0     task:0     snlua protoloader
 :0100000c cpu:0.023255   message:8          mqlen:0     task:1     snlua debug_console 8000  

<CMD:stat OK>
```

# 新增COMMAND.diff_mem

比较前后2次diff_mem指令的内存差异
因没有上次内存记录，所以首次执行显示的是当前使用内存
第三列表示变化状态，共有3个标记[new|change|destroy]
new:上次没记录，本次新增
change: 上次有记录，本次也有记录
destory: 上次有记录，本次没记录

```shell
diff_mem
 :01000007 0.044736 Kb new snlua datacenterd 
 :0100000e 0.047188 Kb new snlua watchdog
 :0100000d 0.048633 Kb new snlua simpledb
 :01000008 0.053174 Kb new snlua service_mgr
 :0100000f 0.055449 Kb new snlua gate
 :0100000b 0.058213 Kb new snlua console
 :01000004 0.059824 Kb new snlua cmaster
 :01000005 0.064414 Kb new snlua cslave
 :0100000c 0.079521 Kb new snlua debug_console 8000
 :0100000a 0.247529 Kb new snlua protoloader
<CMD OK>
```

第二次执行输出结果

```shell
diff_mem
 :0100000d 0.000000 Kb change snlua simpledb 
 :01000005 0.000000 Kb change snlua cslave
 :01000007 0.000000 Kb change snlua datacenterd
 :0100000a 0.000000 Kb change snlua protoloader
 :01000004 0.000000 Kb change snlua cmaster
 :0100000b 0.000000 Kb change snlua console
 :0100000f 0.000000 Kb change snlua gate
 :0100000e 0.000000 Kb change snlua watchdog
 :01000008 0.000000 Kb change snlua service_mgr
 :0100000c 0.007422 Kb change snlua debug_console 8000
```

# 新增.号命令，重复执行上次指令

```shel
stat
 :01000007 cpu:0.005503   message:9          mqlen:0     task:0     snlua datacenterd 
 :0100000e cpu:0.005595   message:12         mqlen:0     task:0     snlua watchdog
 :01000004 cpu:0.006039   message:17         mqlen:0     task:1     snlua cmaster
 :0100000d cpu:0.007463   message:9          mqlen:0     task:0     snlua simpledb
 :0100000b cpu:0.007905   message:10         mqlen:0     task:1     snlua console
 :0100000f cpu:0.009372   message:12         mqlen:0     task:0     snlua gate
 :01000008 cpu:0.011141   message:11         mqlen:0     task:0     snlua service_mgr
 :01000005 cpu:0.01165    message:19         mqlen:0     task:1     snlua cslave
 :0100000a cpu:0.01266    message:9          mqlen:0     task:0     snlua protoloader
 :0100000c cpu:0.023697   message:45         mqlen:0     task:1     snlua debug_console 8000

<CMD:stat OK>
```

执行上次指令stat

```shell
.
<CMD:. OK>
 :01000007 cpu:0.005529   message:10         mqlen:0     task:0     snlua datacenterd
 :0100000e cpu:0.005625   message:13         mqlen:0     task:0     snlua watchdog
 :01000004 cpu:0.006067   message:18         mqlen:0     task:1     snlua cmaster
 :0100000d cpu:0.007489   message:10         mqlen:0     task:0     snlua simpledb
 :0100000b cpu:0.00796    message:11         mqlen:0     task:1     snlua console
 :0100000f cpu:0.0094     message:13         mqlen:0     task:0     snlua gate
 :01000008 cpu:0.011168   message:12         mqlen:0     task:0     snlua service_mgr
 :01000005 cpu:0.011677   message:20         mqlen:0     task:1     snlua cslave
 :0100000a cpu:0.012687   message:10         mqlen:0     task:0     snlua protoloader
 :0100000c cpu:0.026971   message:49         mqlen:0     task:2     snlua debug_console 8000

<CMD:stat OK>
```

.号后还可以跟随2个参数，[执行次数]和[每次间隔秒数]，如下每1秒执行一次上次指令`diff_mem`如次一共执行2次

```shell
diff_mem
 :01000007 0.044736 Kb new snlua datacenterd 
 :0100000e 0.047188 Kb new snlua watchdog
 :0100000d 0.048633 Kb new snlua simpledb
 :01000008 0.053174 Kb new snlua service_mgr
 :0100000f 0.055449 Kb new snlua gate
 :0100000b 0.058213 Kb new snlua console
 :01000004 0.059824 Kb new snlua cmaster
 :01000005 0.064414 Kb new snlua cslave
 :0100000c 0.089766 Kb new snlua debug_console 8000
 :0100000a 0.247529 Kb new snlua protoloader

<CMD:diff_mem OK>
. 2 1

<CMD:. 2 1 OK>
 :0100000a 0.000000 Kb change snlua protoloader
 :0100000e 0.000000 Kb change snlua watchdog
 :01000007 0.000000 Kb change snlua datacenterd
 :0100000f 0.000000 Kb change snlua gate
 :0100000d 0.000000 Kb change snlua simpledb
 :01000004 0.000000 Kb change snlua cmaster
 :01000005 0.000000 Kb change snlua cslave
 :0100000b 0.000000 Kb change snlua console
 :01000008 0.000000 Kb change snlua service_mgr
 :0100000c 0.008799 Kb change snlua debug_console 8000

<CMD:diff_mem OK>
 :0100000a 0.000000 Kb change snlua protoloader 
 :0100000e 0.000000 Kb change snlua watchdog
 :01000007 0.000000 Kb change snlua datacenterd
 :0100000f 0.000000 Kb change snlua gate
 :0100000d 0.000000 Kb change snlua simpledb
 :01000004 0.000000 Kb change snlua cmaster
 :01000005 0.000000 Kb change snlua cslave
 :0100000b 0.000000 Kb change snlua console
 :01000008 0.000000 Kb change snlua service_mgr
 :0100000c 0.007227 Kb change snlua debug_console 8000

<CMD:diff_mem OK>
```
  
  
<b>原文:<br>
<https://lizijie.github.io/2022/11/20/%E5%A2%9E%E5%BC%BAskynet%E4%B8%ADdebug_console.lua%E9%83%A8%E5%88%86%E6%8C%87%E4%BB%A4.html>
<br>
作者github:<br>
<https://github.com/lizijie>
</b>
