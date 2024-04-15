import yarachecker

yara_runner = yarachecker.YaraChecker()
res = yara_runner.run_yara('./scanfolder/')
print(res)