1. 将nuclei_darwin_arm64更换为符合少侠您操作系统的可执行文件
2. 在config.json中填入deepseek的api key，和github token，具体获取方法请百度
3. 对应执行1～4，代码功能见命名
4. 注意代码4，是下载所有github上的符合条件的仓库，因此需要注意打磨github搜索条件的优化，以及仓库数量进行针对性限制，否则需要花8～12小时来下载、整理。或者可以改成第一次全量下载后，其余均通过自动化的方式寻找增量数据。
