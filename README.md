# 长度扩展攻击实现
SM3算法沿用生日攻击的SM3算法，在代码细节上略有改动，分别在SM3函数和IterFunc函数中添加了一个参数vi--初始常量，以便长度扩展攻击的实现

长度扩展攻击主要有以下几步：
1. 对待碰撞的信息m，计算SM3(m)(为了方便输出，没有直接调用SM3函数);
2. 随机生成扩展消息m1;
3. 级联扩展后的m和m1，计算SM3(m||padding||m1)
4. 在m1前面添加|m|个"0"得到m2,将初始常量IV换出SM3(m),计算SM3'(m2).

若3,4步的结果相同，则代表攻击成功。

# 实验结果
![ANIV5S8N(48F8Y2%% TT444](https://user-images.githubusercontent.com/71619888/181758386-c766c011-4477-418f-9751-ad5f0d281ec1.png)
