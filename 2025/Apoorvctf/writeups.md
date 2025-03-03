# Apoorvctf

1. By `HM`
- https://hackmd.io/@hmmm1337/ryLYSEXskx
    - ArchBTW
    - Blend in Disguise

2. By 'Bytecodesky'

# SEO CEO - WEB
They're optimizing SEO to show this garbage?!

> Author: proximuz

[Web chall](https://seo-opal.vercel.app)

At first glance we can not do anything on the page, we do not have any functionality or vulnerability.
Automatically you think of doing reconnaissance, but you can't use automated tools, so you have to do a manual reconnaissance.
we start with the most common of all `/robots.txt`.

and we obtain the following

```
blud really thought itd be that easy
apoorvctf{c0me_0n_mAn_it5_t0o_e4sy}

```
we continue scanning the page, and go to `/sitemap.xml`.

```
<url>
<loc>https://www.thiswebsite.com/goofyahhroute</loc>
<lastmod>2025-02-26</lastmod>
<changefreq>never</changefreq>
<priority>0.0</priority>
</url>
```
and within the whole sitemap we found something interesting, apparently an example page that leads to a certain address, but obviously that domain is not valid, so the directory is a signal.

We enter `/goofyahhroute` and we get this
```
ok bro u da seo master gng frfr ngl no cap
but do you really want the "flag"?
come on blud, it's a yes or no question
yeah?
```

then we can deduce that we must pass the parameter **flag** and as value **yes**.
`/goofyahhroute?flag=yes`
and obtain the flag: `apoorvctf{s30_1snT_0pt1onaL}`


