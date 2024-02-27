# Mon projet API

Ceci est une API construite avec Flask. Elle permet d'authentifier des fichiers audio/video/image en ECC (Elliptic-Curve Crpytography ) et en Dilthium , logiciel permettant une protection théorique a l'arrivée des ordinateurs quantiques

This is an API built with Flask. It can be used to authenticate audio/video/image files in ECC (Elliptic-Curve Crpytography) and Dilthium , software that provides theoretical protection against the arrival of quantum computers.

Это API, созданный с помощью Flask. Его можно использовать для аутентификации аудио/видео/изображений в ECC (Elliptic-Curve Crpytography) и Dilthium, программном обеспечении, обеспечивающем теоретическую защиту от появления квантовых компьютеров.

这是一个使用 Flask 构建的 API。它可用于在 ECC（椭圆曲线加密算法）和 Dilthium（为量子计算机的到来提供理论保护的软件）中验证音频/视频/图像文件。


## Installation

Copiez le répertoire github puis le requirements.txt 

Copy the github directory then the requirements.txt

Скопируйте каталог github, а затем файл requirements.txt.

复制 github 目录，然后复制 requirements.txt

## Utilisation

Appelez l'API en précisant les chemiers locals des fichiers que vous voulez traitez avec le bon url d'endpoint juste aprés avoir lancée le serveur avec gunicorn 


Call the API, specifying the locals of the files you want to process with the correct endpoint url, just after launching the server with gunicorn 


Вызовите API, указав локали файлов, которые вы хотите обработать, с правильным url конечной точки сразу после запуска сервера с помощью примера gunicorn:


使用 gunicorn 示例启动服务器后，使用正确的端点 url 指定要处理的文件的本地地址，从而调用 API：
