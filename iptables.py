import subprocess

def main(port, subnets):
    subnets_str = ['%s/%d' % (ip,width) for ip,width in subnets]
    subprocess.call(['./ipt', str(port)] + subnets_str)
