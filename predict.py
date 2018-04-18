from featureextractor import featureextractor
from scipy.special import expit
import numpy as np
def preidict(str):
    temp=featureextractor(str)
    feature=[]
    feature.append(1)
    for i in range(0,len(temp)):
        feature.append(temp[i])

    feature=np.array(feature)

    theta=([
        -0.905877,
        1.474401,
        0.508719,
        - 0.633691,
        0.470666,
        - 0.312943,
        2.966641,
        2.875487,
        8.158240,
        - 2.047143,
        0.304662,
        0.488862,
        - 0.325627,
        2.664044,
        6.269800,
        2.363358,
        2.253615,
        0.461469,
        - 0.370708,
        - 0.356877,
        0.325309,
        - 0.095074,
        1.224013,
        1.076416,
        3.245338,
        0.724740])
    theta=np.array(theta)


    temp=np.dot(feature,theta)
    temp=expit(temp)

    if temp>=0.5:
        return 1
    else:
        return 0


link = 'http://www.scipy-lectures.org/intro/numpy/operations.html'
print(featureextractor(link))
print(preidict(link))
