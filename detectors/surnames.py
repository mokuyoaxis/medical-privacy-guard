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
    # Added after a released-text defect: the adjacent form stopped mid-name
    # for given characters outside this inventory. Kept to characters that are
    # overwhelmingly given names rather than ordinary words, so clinical prose
    # is not read as a person.
    "婷妍婉珊媛娅姗姝婧婕妤茜蕾薇蓉菲芸芊蕊沁瑶琪琳璐瑾瑜瑄玥彤悦莹颖倩晴"
    "浩睿宸昊泽霖铭煜烨熙辰皓弘骏靖翊峻崇琛珩珏璋琦珂珺鑫曦涵爽钧锐锦凯"
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

#: Words that legitimately follow a personal name in a clinical note: clinical
#: verbs, connectives, and the labels of the next field.
#:
#: A *labelled* name ("责任护士：郑爽") is captured with this boundary instead
#: of the inventory, because the inventory cannot be complete: 爽, 鑫 and 曦 are
#: ordinary given-name characters outside it, and an inventory-bounded capture
#: stops at the surname and releases the rest of the name as residual PHI.
#: A name with no delimiter has nothing to anchor its end, so the adjacent form
#: still uses the inventory.
NAME_FOLLOW_BOUNDARY: str = (
    r"(?:入院|出院|就诊|住院|治疗|复查|随访|主诉|既往|收入|转入|转科|"
    r"查房|病情|陪同|签字|执行|查看|测量|交接|表示|同意|拒绝|要求|建议|"
    r"否认|"
    r"自述|护理|看护|照料|负责|操作|实施|完成|给予|服用|注射|检查|化验|"
    r"告知|交代|说明|询问|签署|确认|办理|准备|安排|护送|转运|接收|进入|"
    r"离开|返回|因|于|诉|在|自|伴|拟|系|之|由|"
    r"电话|手机|邮箱|身份证|证件|病历号|住院号|就诊号|地址|住址|诊断|"
    r"症状|用药|医生|医师|大夫|护士|护师)"
)
