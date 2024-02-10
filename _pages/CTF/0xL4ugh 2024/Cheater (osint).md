---
title: "OSINT: Cheater (medium)"
date: "2024-02-10"
thumbnail: "/assets/img/thumbnail/0xl4ugh24.png"
---

# Description
---

Our team received a request from a man who believes his wife may be cheating on him. He asked us to help by checking her accounts for any evidence. He provided his wife's name, "Hamdia Eldhkawy" and mentioned that a friend informed him she shared a picture with someone on social media. He couldn't find the image and wants us to discover the man's real name.

Flag Format: 0xL4ugh{First Name_Last Name}

# Solution
---

Let's go

- First i started searching using `Hamdia Eldhkawy` using google
- after some trials i found nothing useful
- I decided to try searching for `Hamdia Eldhkawy` using bing search
- good news, i found an instagram profile <a href="https://www.instagram.com/hamdia_elhob_kolo/">instagram_profile</a>
- I searched within the profile trying to get useful information for next steps examining
    - followers
    - posts

- I stuck for a long time here as i thought the followers or the people reacting to her posts maybe interesting, so i spent some time with some reacting users but with no useful information
- I also tried using the pictures in her posts in reverse image search, but also with no useful results
- Then i noticed important thing that all the posts are about AI generated pictures
- This may indicate that she is interested in AI and this gave me a hint to the next step
- Let's go back to bing and search using `Hamdia Eldhkawy ai`
- and we got this results

<img src="/assets/img/0xl4ugh24/cheater.jpg">

- The OPENAI link is the treasure here <a href="https://community.openai.com/t/i-really-love-this-colorful-drawings/616450">OPENAI post</a>
- When we go in we find interesting comment from a user called `Hamada_Elbes`

<img src="/assets/img/0xl4ugh24/cheater2.jpg">

- I remember you, Hamada
> Hamade_Elbes was an OSINT challange in 0xl4ugh ctf 2023 xDDDD
- anyway let's back and look at the comment
- The comment is: `Haha Hamdia, I already caught that :wink: I can share it with your husband <3` with the photo below

<img src="/assets/img/0xl4ugh24/cheater1.jpg">

- After analyzing this image carefully we will find important information
    - First, The url may move us to the post
    - Second, Hamdia mentioned her boyfriend in the post but the picture is cropped so we just know that his account starts by `spide` and this's not enough
- When we try to access the link in the image we willn't get that post
- Maybe Hamdia deleted it ummmmmmmmmmmmmm
- Good one, Hamdia but you are too late as Hamada_Elbes caught you xDD

- We need to reach that deleted post and in this situation we will think abount web archiving
- I tried `wayback machine` but with no useful results
- Then i searched for an alternative and after many trials this worked with me <a href="https://archive.ph/">archive.ph</a>

<img src="/assets/img/0xl4ugh24/cheater3.jpg">

- Let's open it and get the info we need

<img src="/assets/img/0xl4ugh24/cheater4.jpg">

- The treasures in here finally she mentioned `spidersh4zly`
- What are you waiting for?! Let's search for him on instagram
- And this is his account

<img src="/assets/img/0xl4ugh24/cheater5.jpg">

- There's another link in his profile for more information, and i see that there's nothing else important
- Let's go to this link

<img src="/assets/img/0xl4ugh24/cheater6.jpg">

- We see many accounts for spidersh4zly after analyzing them i found that all are useless except the gmail
- We can use the gmail in getting his real name using a powerful tool called <a href="https://epieos.com/">epieos</a>
- Go to its site insert the email and let it makes its magic
- And here's the results

<img src="/assets/img/0xl4ugh24/cheater7.jpg">

- We found him. He is `Abdelfatah ElCanaway`

<img src="/assets/img/0xl4ugh24/cheater8.jpg">

Congratz we got it.
The flag: `0xL4ugh{Abdelfatah_ElCanaway}`