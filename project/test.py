from PIL import Image

img = Image.open("D:/D Drive/Studies/BCA 6/Final Year Project/project/static/profile_pics/default.jpg")
print(img)
img.thumbnail((200,200))
img.save("D:/D Drive/Studies/BCA 6/Final Year Project/project/static/profile_pics/default2.jpg")
print(img)
img.show()