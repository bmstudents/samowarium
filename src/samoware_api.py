# TODO: причесать вызовы aiohttp
import html
from datetime import datetime
from http.client import HTTPResponse
from http.cookies import SimpleCookie
from typing import Self

import re
import logging as log
import bs4 as bs
import xml.etree.ElementTree as ET
from aiohttp import ClientSession, ClientTimeout
from urllib.error import HTTPError

import env
from const import (
    HTTP_COMMON_TIMEOUT_SEC,
    HTTP_CONNECT_LONGPOLL_TIMEOUT_SEC,
    HTTP_FILE_LOAD_TIMEOUT_SEC,
    HTTP_TOTAL_LONGPOLL_TIMEOUT_SEC,
)
import metrics

SESSION_TOKEN_PATTERN = re.compile("^[0-9]{6}-[a-zA-Z0-9]{20}$")

AGGRESSIVE_FORMAT_LETTER = True


class UnauthorizedError(Exception):
    pass


class SamowarePollingContext:
    def __init__(
        self,
        session: str = "",
        request_id: int = 0,
        rand: int = 0,
        command_id: int = 0,
        ack_seq: int = 0,
        cookies: SimpleCookie = SimpleCookie(),
    ) -> None:
        self.session = session
        self.request_id = request_id
        self.rand = rand
        self.command_id = command_id
        self.ack_seq = ack_seq
        self.cookies = cookies

    def make_next(
        self,
        session: str | None = None,
        request_id: int | None = None,
        rand: int | None = None,
        command_id: int | None = None,
        ack_seq: int | None = None,
        cookies: SimpleCookie | None = None,
    ) -> Self:
        return SamowarePollingContext(
            session=self.session if session is None else session,
            command_id=self.command_id if command_id is None else command_id,
            cookies=self.cookies if cookies is None else cookies,
            ack_seq=self.ack_seq if ack_seq is None else ack_seq,
            rand=self.rand if rand is None else rand,
            request_id=self.request_id if request_id is None else request_id,
        )


class MailHeader:
    def __init__(
        self,
        uid: str,
        flags: str,
        local_time: datetime,
        utc_time: datetime,
        recipients: tuple[str, str],
        from_mail: str,
        from_name: str,
        subject: str,
    ) -> None:
        self.uid = uid
        self.flags = flags
        self.local_time = local_time
        self.utc_time = utc_time
        self.recipients = recipients
        self.from_mail = from_mail
        self.from_name = from_name
        self.subject = subject


class MailBody:
    def __init__(self, text: str, attachments: list[tuple[HTTPResponse, str]]):
        self.text = text
        self.attachments = attachments


class Mail:
    def __init__(self, header: MailHeader, body: MailBody):
        self.header = header
        self.body = body


async def login(login: str, password: str) -> SamowarePollingContext | None:
    log.debug(f"logging in for {login}")

    url = "https://mailstudent.bmstu.ru/XIMSSLogin/"
    params = {
        "errorAsXML": "1",
        "EnableUseCookie": "1",
        "x2auth": "1",
        "canUpdatePwd": "1",
        "version": "6.1",
        "userName": login,
    }
    if SESSION_TOKEN_PATTERN.match(password):
        params["sessionid"] = password
    else:
        params["password"] = password
    if not env.is_ip_check_enabled():
        params["DisableIPWatch"] = "1"

    async with ClientSession(
        timeout=ClientTimeout(sock_read=HTTP_COMMON_TIMEOUT_SEC),
    ) as http_session:
        response = await http_session.get(url, params=params)
        metrics.samoware_response_status_code_metric.labels(sc=response.status).inc()

        tree = ET.fromstring(await response.text())
        if tree.find("session") is None:
            log.debug(f"logging in response ({login}) does not have session tag")
            if tree.find("response").attrib["errorText"] in (
                "incorrect password or account name",
                "failed to route the address",
                "incorrect E-mail address",
            ):
                raise UnauthorizedError
            else:
                raise HTTPError(
                    url=url,
                    code=response.status,
                    msg=(await response.text()),
                    hdrs=None,
                    fp=None,
                )

        session = tree.find("session").attrib["urlID"]

        log.debug(f"successful login for {login}")
        return SamowarePollingContext(session=session)


async def revalidate(login: str, session: str) -> SamowarePollingContext | None:
    log.debug(f"revalidating session for {login}")

    url = "https://mailstudent.bmstu.ru/XIMSSLogin/"
    params = {
        "errorAsXML": "1",
        "EnableUseCookie": "1",
        "x2auth": "1",
        "canUpdatePwd": "1",
        "version": "6.1",
        "userName": login,
        "sessionid": session,
    }
    if not env.is_ip_check_enabled():
        params["DisableIPWatch"] = "1"

    async with ClientSession(
        timeout=ClientTimeout(sock_read=HTTP_COMMON_TIMEOUT_SEC),
    ) as http_session:
        response = await http_session.get(url, params=params)
        metrics.samoware_response_status_code_metric.labels(sc=response.status).inc()

        tree = ET.fromstring(await response.text())
        if tree.find("session") is None:
            log.debug(f"revalidation response ({login}) does not have session tag")
            if (
                tree.find("response").attrib["errorText"]
                == "incorrect password or account name"
            ):
                raise UnauthorizedError
            else:
                raise HTTPError(
                    url=url, code=response.status, msg=(await response.text())
                )

        new_session = tree.find("session").attrib["urlID"]
        log.debug(f"successful revalidation {login}")

        return SamowarePollingContext(session=new_session)


async def longpoll_updates(
    context: SamowarePollingContext,
) -> tuple[str, SamowarePollingContext]:
    async with ClientSession(
        timeout=ClientTimeout(
            connect=HTTP_CONNECT_LONGPOLL_TIMEOUT_SEC,
            total=HTTP_TOTAL_LONGPOLL_TIMEOUT_SEC,
        )
    ) as http_session:
        url = f"https://student.bmstu.ru/Session/{context.session}/?ackSeq={context.ack_seq}&maxWait=20&random={context.rand}"
        response = await http_session.get(
            url=url,
            cookies=context.cookies,
        )

        metrics.samoware_response_status_code_metric.labels(sc=response.status).inc()
        response_text = await response.text()
        log.debug(
            f"samoware longpoll response code: {response.status}, text: {response_text}"
        )
        if response.status == 550:
            log.warning(
                f"received 550 code in longPollUpdates - Samoware Unauthorized. response: {response_text}"
            )
            raise UnauthorizedError
        if response.status != 200:
            log.error(
                f"received non 200 code in longPollUpdates: {response.status}. response: {response_text}"
            )
            raise HTTPError(url=url, code=response.status, msg=(await response.text()))
        tree = ET.fromstring(response_text)
        ack_seq = context.ack_seq
        if "respSeq" in tree.attrib:
            ack_seq = int(tree.attrib["respSeq"])
        return (
            response_text,
            context.make_next(ack_seq=ack_seq, rand=context.rand + 1),
        )


async def get_new_mails(
    context: SamowarePollingContext,
) -> tuple[list[MailHeader], SamowarePollingContext]:
    async with ClientSession(
        timeout=ClientTimeout(sock_read=HTTP_COMMON_TIMEOUT_SEC),
        cookies=context.cookies,
    ) as http_session:
        url = f"https://student.bmstu.ru/Session/{context.session}/sync?reqSeq={context.request_id}&random={context.rand}"
        response = await http_session.get(
            url=url,
            data=f'<XIMSS><folderSync folder="INBOX-MM-1" limit="300" id="{context.command_id}"/></XIMSS>',
            cookies=context.cookies,
            timeout=HTTP_COMMON_TIMEOUT_SEC,
        )
        metrics.samoware_response_status_code_metric.labels(sc=response.status).inc()

        if response.status == 550:
            log.warning(
                f"received 550 code in getInboxUpdates - Samoware Unauthorized. response: {await response.text()}"
            )
            raise UnauthorizedError
        if response.status != 200:
            log.error(
                f"received non 200 code in getInboxUpdates: {response.status}. response: {await response.text()}"
            )
            raise HTTPError(
                url=url, code=response.status, msg=(await response.text()), hdrs=None
            )
        tree = ET.fromstring(await response.text())
        mail_headers = []
        for element in tree.findall("folderReport"):
            log.debug("folderReport: " + str(ET.tostring(element, encoding="utf8")))
            if element.attrib["mode"] == "added":
                uid = element.attrib["UID"]
                local_time = datetime.strptime(
                    element.find("INTERNALDATE").attrib["localTime"], "%Y%m%dT%H%M%S"
                )
                utc_time = datetime.strptime(
                    element.find("INTERNALDATE").text, "%Y%m%dT%H%M%SZ"
                )
                flags = element.find("FLAGS").text
                from_mail = element.find("E-From").text
                if "realName" in element.find("E-From").attrib:
                    from_name = element.find("E-From").attrib["realName"]
                else:
                    from_name = element.find("E-From").text
                if (
                    element.find("Subject") is not None
                    and element.find("Subject").text is not None
                ):
                    subject = html.escape(element.find("Subject").text)
                else:
                    subject = "Письмо без темы"
                to = []
                for el in element.findall("E-To"):
                    to_mail = el.text
                    if "realName" in el.attrib:
                        to_name = el.attrib["realName"]
                    else:
                        to_name = el.text
                    to.append((to_mail, to_name))

                mail_headers.append(
                    MailHeader(
                        flags=flags,
                        from_mail=from_mail,
                        from_name=from_name,
                        local_time=local_time,
                        subject=subject,
                        recipients=to,
                        uid=uid,
                        utc_time=utc_time,
                    )
                )
        return (
            mail_headers,
            context.make_next(
                request_id=context.request_id + 1,
                rand=context.rand + 1,
                command_id=context.command_id + 1,
            ),
        )


async def set_session_info(context: SamowarePollingContext) -> SamowarePollingContext:
    async with ClientSession(
        timeout=ClientTimeout(sock_read=HTTP_COMMON_TIMEOUT_SEC),
        cookies=context.cookies,
    ) as http_session:
        response = await http_session.post(
            url=f"https://student.bmstu.ru/Session/{context.session}/sync?reqSeq={context.request_id}&random={context.rand}",
            data='<XIMSS><prefsRead id="1"><name>Language</name></prefsRead></XIMSS>',
        )
        metrics.samoware_response_status_code_metric.labels(sc=response.status).inc()

        await http_session.post(
            f"https://student.bmstu.ru/Session/{context.session}/sessionadmin.wcgp",
            data={
                "op": "setSessionInfo",
                "paramType": "json",
                "param": '{"platform":"Linux x86_64","clientName":"hSamoware","browser":"Firefox 122"}',
                "session": context.session,
            },
        )
        return context.make_next(
            cookies=response.cookies,
            request_id=context.request_id + 1,
            rand=context.rand + 1,
        )


async def open_inbox(context: SamowarePollingContext) -> SamowarePollingContext:
    url = f"https://student.bmstu.ru/Session/{context.session}/sync?reqSeq={context.request_id}&random={context.rand}"
    data = f"""<XIMSS>
            <listKnownValues id="{context.command_id}"/>
            <mailboxList filter="%" pureFolder="yes" id="{context.command_id + 1}"/>
            <mailboxList filter="%/%" pureFolder="yes" id="{context.command_id + 2}"/>
            <folderOpen mailbox="INBOX" sortField="INTERNALDATE" sortOrder="desc" folder="INBOX-MM-1" id="{context.command_id + 3}">
                <field>FLAGS</field>
                <field>E-From</field>
                <field>Subject</field>
                <field>Pty</field>
                <field>Content-Type</field>
                <field>INTERNALDATE</field>
                <field>SIZE</field>
                <field>E-To</field>
                <field>E-Cc</field>
                <field>E-Reply-To</field>
                <field>X-Color</field>
                <field>Disposition-Notification-To</field>
                <field>X-Request-DSN</field>
                <field>References</field>
                <field>Message-ID</field>
            </folderOpen>
            <setSessionOption name="reportMailboxChanges" value="yes" id="{context.command_id + 4}"/>
        </XIMSS>"""
    async with ClientSession(
        timeout=ClientTimeout(sock_read=HTTP_COMMON_TIMEOUT_SEC),
        cookies=context.cookies,
    ) as http_session:
        response = await http_session.get(url, data=data)
        metrics.samoware_response_status_code_metric.labels(sc=response.status).inc()

        if response.status == 550:
            log.error(
                f"received 550 code in openInbox - Samoware Unauthorized. response: {await response.text()}"
            )
            raise UnauthorizedError
        if response.status != 200:
            log.error(
                f"received non 200 code in openInbox: {response.status}. response: {await response.text()}"
            )
            raise HTTPError(
                url=url, code=response.status, msg=(await response.text()), hdrs=None
            )

        return context.make_next(
            request_id=context.request_id + 1,
            rand=context.rand + 1,
            command_id=context.command_id + 5,
        )


async def get_mail_body_by_id(context: SamowarePollingContext, uid: str) -> MailBody:
    url = f"https://student.bmstu.ru/Session/{context.session}/FORMAT/Samoware/INBOX-MM-1/{uid}"
    async with ClientSession(
        timeout=ClientTimeout(sock_read=HTTP_COMMON_TIMEOUT_SEC),
        cookies=context.cookies,
    ) as http_session:
        response = await http_session.get(url)
        metrics.samoware_response_status_code_metric.labels(sc=response.status).inc()

        if response.status == 550:
            log.error(
                f"received 550 code in getMailBodyById - Samoware Unauthorized\nresponse: {await response.text()}"
            )
            raise UnauthorizedError
        if response.status != 200:
            log.error(
                f"received non 200 code in getMailBodyById: {response.status}\nresponse: {await response.text()}"
            )
            raise HTTPError(
                url=url, code=response.status, msg=(await response.text()), hdrs=None
            )
        tree = bs.BeautifulSoup((await response.text()), "html.parser")
        mailBodiesHtml = tree.findAll("div", {"class": "samoware-RFC822-body"})

        text = ""
        for mailBodyHtml in mailBodiesHtml:
            log.info("mail body: " + str(mailBodyHtml))
            foundTextBeg = False
            for element in mailBodyHtml.children:
                if (
                    isinstance(element, bs.Tag)
                    and element.has_attr("class")
                    and "textBeg" in element["class"]
                ):
                    foundTextBeg = True
                    log.debug("found textBeg")
                if (
                    isinstance(element, bs.Tag)
                    and element.has_attr("class")
                    and "textEnd" in element["class"]
                ):
                    log.debug("found textEnd")
                    break
                if foundTextBeg:
                    text += html_element_to_text(element)

        text = re.sub(r"(\r)+", "\r", text).strip()
        text = re.sub(r"(\n)+", "\n", text).strip()
        text = text.replace("\r", "\n\n")
        if AGGRESSIVE_FORMAT_LETTER:
            text = text.replace("\n\xa0\n", "\n\n")
        text = re.sub(r"(\n){2,}", "\n\n", text).strip()

        attachments = []
        for attachment_html in tree.find_all("cg-message-attachment"):
            attachment_url = (
                "https://student.bmstu.ru" + attachment_html["attachment-ref"]
            )
            file = await (
                await http_session.get(
                    attachment_url,
                    timeout=HTTP_FILE_LOAD_TIMEOUT_SEC,
                )
            ).read()
            name = attachment_html["attachment-name"]
            attachments.append((file, name))
        return MailBody(text, attachments)


async def mark_as_read(
    context: SamowarePollingContext, uid: str
) -> SamowarePollingContext:
    url = f"https://student.bmstu.ru/Session/{context.session}/sync?reqSeq={context.request_id}&random={context.rand}"
    data = f'<XIMSS><messageMark flags="Read" folder="INBOX-MM-1" id="{context.command_id}"><UID>{uid}</UID></messageMark></XIMSS>'
    async with ClientSession(
        timeout=ClientTimeout(sock_read=HTTP_COMMON_TIMEOUT_SEC),
        cookies=context.cookies,
    ) as http_session:
        response = await http_session.post(url=url, data=data)
        metrics.samoware_response_status_code_metric.labels(sc=response.status).inc()

        if response.status == 550:
            log.error(
                f"received 550 code in mark_as_read - Samoware Unauthorized\nresponse: {await response.text()}"
            )
            raise UnauthorizedError
        if response.status != 200:
            log.error(
                f"received non 200 code in mark_as_read: {response.status}\nresponse: {await response.text()}"
            )
            raise HTTPError(
                url=url, code=response.status, msg=(await response.text()), hdrs=None
            )
        return context.make_next(
            request_id=context.request_id + 1,
            rand=context.rand + 1,
            command_id=context.command_id + 1,
        )


def html_element_to_text(element):
    log.debug(f"converting html element to text: {element}")
    if isinstance(element, bs.NavigableString):
        return html.escape(
            re.sub(
                r" +",
                " ",
                str(element).replace("\r", "").strip("\n").replace("\n", " "),
            )
        )
    elif isinstance(element, bs.Tag):
        if element.name == "a" and "href" in element.attrs:
            href = element["href"]
            text = f"\\[{"".join(html_element_to_text(x) for x in element.children)}\\]\\({href}\\)"
            return text
        elif element.name == "style":
            return ""
        elif element.name == "br":
            return "\n"
        elif element.name == "strong" or element.name == "b":
            return "\\*"
        elif element.name == "&quot;":
            return "\""
        elif element.name == "hr":
            return "\n----------\n"
        elif element.name == "p":
            text = ""
            for child in element.children:
                text += html_element_to_text(child)
            return "\r" + text + "\r"
        elif element.name == "div":
            text = ""
            for child in element.children:
                text += html_element_to_text(child)
            return "\n" + text + "\n"
        elif element.name == "li":
            text = ""
            for child in element.children:
                text += html_element_to_text(child)
            return text + "\n"
        elif element.name == "blockquote":
            text = ""
            for child in element.children:
                text += html_element_to_text(child)
            return "```" + text.strip() + "```"
        else:
            text = ""
            for child in element.children:
                text += html_element_to_text(child)
            return text

def has_updates(response: str) -> bool:
    return '<folderReport folder="INBOX-MM-1" mode="notify"/>' in response
