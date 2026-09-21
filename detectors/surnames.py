"""Common Chinese surname inventory.

Several detectors need "this looks like a personal name" as a weak prior:
person names after a field label, staff names before a title, relatives named
in the history. A character-class rule without this anchor produces
unacceptable false positives because ordinary clinical words sit directly
after the labels ("患者住院号…" would yield the name "住院号").

The list holds the ~120 most common surnames by modern frequency, not the
classical 《百家姓》 ordering (which omits high-frequency names such as 刘 and
陈 from its early lines). Names outside it can be missed; downstream checks
using the same inventory cannot establish that such names are absent.
"""

from __future__ import annotations

SURNAMES: str = (
    "王李张刘陈杨黄赵吴周徐孙马朱胡郭何高林罗郑梁谢宋唐许韩冯邓曹彭曾"
    "肖田董袁潘于蒋蔡余杜叶程苏魏吕丁任沈姚卢姜崔钟谭陆汪范金石廖贾夏"
    "韦付方白邹孟熊秦邱江尹薛闫段雷侯龙史陶黎贺顾毛郝龚邵万钱严覃武戴"
    "莫孔向汤常温康施文牛樊葛邢安齐易乔伍庞颜倪庄聂章鲁岳翟殷詹申欧耿"
    "关兰焦俞左柳甘祝包宁尚符舒阮柯纪梅童凌毕单季裴霍涂成苗谷盛曲翁冉"
)

#: Character class matching one surname: ``[赵钱孙李…]``.
SURNAME_CLASS: str = f"[{SURNAMES}]"

#: Characters commonly used in Chinese given names.
#:
#: A plain ``[\u4e00-\u9fff]{1,2}`` for the given name cannot be bounded
#: correctly: greedy matching swallows the following verb ("其妻王芳陪同" →
#: "王芳陪"), while non-greedy matching stops at the surname ("王芳" → "王").
#: Anchoring the given-name part on a name-character inventory resolves both:
#: "陪" is not a name character, so the match ends at 芳. 某 is included
#: because anonymous forms ("李某", "张某某") are extremely common in notes.
GIVEN_CHARS: str = (
    "某伟芳娜敏静磊军洋勇艳杰娟涛明超秀兰桂英玉梅建国淑"
    "芬海燕文博思远雅丽华强平刚毅鹏辉宇轩晨阳雪松柏青"
    "志晓小红春秋菊冬珍爱民生新庆永花凤金银香竹林树大"
    "武立学峰龙江山河彩霞云东亚楠男琴君嘉佳怡慧俊天佑"
    "德波瑞"
)

#: Zero to two given-name characters drawn from the name inventory.
GIVEN_CLASS: str = f"[{GIVEN_CHARS}]{{0,2}}"

#: One or two given-name characters drawn from the name inventory.
#:
#: ``GIVEN_CLASS`` above allows zero characters, which is right for titled forms
#: ("王医生") but too loose for the adjacent person-field form: a zero-length
#: given name lets an ordinary word be read as a name ("患者周转正常" -> 周 +
#: 转正常).
GIVEN_NAME_CLASS: str = f"[{GIVEN_CHARS}]{{1,2}}"

#: Common two-character (compound) surnames. Matched before the single-character
#: class so 欧阳娜娜 reads as 欧阳 + 娜娜 rather than 欧 + 阳娜娜.
COMPOUND_SURNAME_CLASS: str = (
    "(?:欧阳|司马|上官|诸葛|东方|独孤|南宫|西门|夏侯|皇甫|尉迟|公孙|"
    "慕容|司徒|令狐|宇文|长孙|轩辕|赫连|澹台|公冶|宗政|濮阳|淳于|"
    "太叔|申屠|仲孙|钟离|鲜于|闾丘|司空|端木|巫马|公西|漆雕|乐正|"
    "拓跋|百里|东郭|南门|呼延|羊舌|微生|梁丘|左丘|第五)"
)

#: Digits used as placeholder given names in notes and tests (张三, 李四).
NUMERAL_GIVEN_CLASS: str = "[一二三四五六七八九十]"
