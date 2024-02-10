---
title: "OSINT: Lost In History (easy)"
date: "2024-02-10"
thumbnail: "/assets/img/thumbnail/0xl4ugh24.png"
---

# Description
---

MM0X and xElessaway were in a mission to find someone but seems they had a stalker and got us this picture of them both. can you identify the place they were?

<img src="/assets/img/0xl4ugh24/lost in history.jpg" alt="lost in history.jpg" width=500px>

Flag Format: 0xL4ugh{The Name of the place with spaces}


# solution
---

Let's go 

- after analyzing the image i found some notes which may be important

<img src="/assets/img/0xl4ugh24/lost in history1.jpg" alt="lost in history.jpg1" width=500px>

- They are numbered in this img
    - label 1: a reflection of a word
    - label 2&3: are statues

- The word in label one after zooming and guessing the rest of the word i believe it's 'المومياوات' 
- The statues are indication that this may be a museum
- So when i searched using 'متحف المومياوات' i found this result

<img src="/assets/img/0xl4ugh24/lost in history2.jpg" alt="lost in history.jpg1" width=500px>

The place is `The national museum of Egyptian Civilization` and you can confirm that by searching for photos of this museum
Then the flag is `0xL4ugh{The national museum of Egyptian Civilization}`