
import ast
import asyncio
import inspect
import re
import sqlite3
import sys
from textwrap import TextWrapper
from urllib.parse import urljoin, quote as urlquote

import aiohttp
from lxml.html import (document_fromstring as parse_html,
                       tostring as unparse_html)
import uvloop

base_url = 'http://www.secretariasenado.gov.co/'

numeric_escape_match = re.compile(r'&#(\d+);')
email_match = re.compile(r'\n var addy\d+ = (.*);\n addy\d+ = addy\d+ \+ (.*);')

loop = uvloop.new_event_loop()


def _log(message, _wrap=TextWrapper(break_long_words=False, break_on_hyphens=False,
                                    width=68).wrap):
    print('\n'.join((inspect.stack()[1].function,
                     *('  ' + m for m in _wrap(message)))
                    ), file=sys.stderr)


def deobfuscate_email(matches):
    email = ''.join(ast.literal_eval(i.strip())
                    for m in matches
                    for i in m.split('+'))
    email = numeric_escape_match.sub(lambda m: chr(int(m.group(1))), email)
    email = email.strip('-')
    return email


async def scrape_person(session, semaphore, params):
    def extract_emails():
        emails = unparse_html(source).decode()
        emails = [deobfuscate_email(m.groups())
                  for m in email_match.finditer(emails)]
        if not emails:
            _log("Couldn't find email in " + profile_resp.url)
            return
        return ';'.join(sorted(emails,
                               key=lambda i: 0 if 'senado.gov.co' in i else 1))

    async def extract_photo():
        try:
            photo, = source.xpath('.//img[1]/@src')
        except ValueError:
            return
        async with semaphore, \
                session.head(urljoin(base_url, urlquote(photo))) as photo_resp:
            if photo_resp.status == 200:
                return photo_resp.url
        _log('Discarding {} in {}.  Received error code {}'
             .format(photo_resp.url, profile_resp.url, photo_resp.status))

    def extract_other_item(caption, link=False):
        if isinstance(caption, tuple):
            return next(filter(None, (extract_other_item(i, link) for i in caption)),
                        None)
        if link:
            return next(iter(source.xpath('''\
.//td[contains(string(.), "{}")]/following-sibling::td//a/@href'''.format(
                caption))), None)
        else:
            val = ''.join(source.xpath('''\
string(.//td[contains(string(.), "{}")]/following-sibling::td)'''.format(
                caption))).strip()
            if not val or val.lower() in {'no tine', 'no tiene'}:
                return
        return val

    def extract_facebook():
        facebook = (extract_other_item('FACEBOOK:', link=True) or
                    extract_other_item('FACEBOOK:'))
        if not facebook:
            return

        if facebook.startswith(('facebook.com', '/facebook.com')):
            facebook = 'https://www.' + facebook.lstrip('/')
        elif facebook.startswith('http://social.facebook.com/'):
            facebook = facebook.replace('http://social.facebook.com/',
                                        'https://www.facebook.com/')
        elif not facebook.startswith('http'):
            facebook = urljoin('https://www.facebook.com/', facebook)
        return facebook

    def extract_twitter():
        twitter = extract_other_item('TWITTER:')
        if twitter:
            twitter = twitter.replace('https://twitter.com/', '').lstrip('@')
        return twitter

    async def extract_website():
        website = extract_other_item(('PAGINA WEB:', 'PÁGINA WEB:'), link=True)
        if not website or 'alvaroasthongiraldo' in website:
            website = extract_other_item(('PAGINA WEB:', 'PÁGINA WEB:'))
            if not website:
                return
            if not website.startswith('http'):
                website = ('http://' + website).rstrip(',')
        elif website == '/false' or 'mailto:' in website:
                return
        try:
            with aiohttp.Timeout(5, loop=loop):
                async with session.head(website) as website_resp:
                    ...
        except aiohttp.errors.ClientError as e:
            _log('Discarding {} in {}.  {}'
                 .format(website, profile_resp.url, e.args[1]))
            return
        except asyncio.TimeoutError as e:
            _log('{} was unresponsive in {}.  {}'.format(e.args[1]))
        return website_resp.url

    async with semaphore, session.get(base_url, params=sorted(params.items())) \
            as profile_resp:
        source, = (parse_html(await profile_resp.text())
                   .xpath('//div[@class = "art-article"]'))
    return (params['id'],
            source.text_content().strip().splitlines()[0].strip(),
            (await extract_photo()),
            extract_other_item('FILIACIÓN POLÍTICA:'),
            '2014',
            extract_emails(),
            (await extract_website()),
            extract_other_item('TELÉFONO:'),
            extract_facebook(),
            extract_twitter(),
            extract_other_item('LUGAR DE NACIMIENTO:'),
            profile_resp.url)


async def gather_people(session, semaphore):
    async with session.get(base_url + 'index.php/buscar-senador') as resp:
        source = parse_html(await resp.text())
    base_params = dict(i.xpath('./@name | ./@value')
                       for i in source.xpath('//form[@name = "ddaForm"]'
                                             '/input[@type = "hidden"]'))
    people_ids = source.xpath('//form[@name = "ddaForm"]/select[@name = "id"]'
                              '/option[position() > 1]/@value')
    people = await asyncio.gather(*(scrape_person(session, semaphore,
                                                  {**base_params, 'id': i})
                                    for i in people_ids), loop=loop)
    return people


def main():
    with aiohttp.ClientSession(loop=loop) as session, \
            sqlite3.connect('data.sqlite') as cursor:
        people = loop.run_until_complete(gather_people(
            session, asyncio.Semaphore(10, loop=loop)))
        cursor.execute('''\
CREATE TABLE IF NOT EXISTS data
(id, name, image, 'group', term, email, website, phone, facebook, twitter,
 place_of_birth, source, UNIQUE (id))''')
        cursor.executemany('''\
INSERT OR REPLACE INTO data VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            people)

if __name__ == '__main__':
    main()
