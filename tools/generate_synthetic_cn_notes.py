#!/usr/bin/env python3
"""Synthetic Chinese clinical note generator.

Builds a deterministic corpus of fabricated Chinese clinical notes with
character-level span annotations, for benchmarking the guard.

The corpus has two halves. Positive documents carry labelled identifiers and
measure recall. Negative documents carry clinical content and no identifier at
all, so any span-level fact detected in one is a false positive by
construction — they are the only place over-redaction is observable.

Everything produced here is synthetic:

- names come from small common-surname / given-name pools;
- mobile numbers use the ``138000`` placeholder prefix already used in the
  project README (never a real subscriber number);
- resident IDs use real administrative prefixes over fabricated birth dates
  and sequence numbers, with a valid GB 11643-1999 check digit so the
  detector's check-digit path is exercised;
- emails and URLs use reserved example domains (example.com / example.org);
- IP addresses use RFC 5737 TEST-NET ranges (192.0.2.0/24, 198.51.100.0/24);
- addresses use real district names with invented street/building details;
- landlines use public area codes with invented local numbers.

No content is derived from a real patient record, EHR export, research
dataset, audit log or breach report.

Usage::

    python tools/generate_synthetic_cn_notes.py --out tests/fixtures/synthetic_cn_notes

The corpus is reproducible: the same ``--seed`` always yields byte-identical
output, and each document derives its own RNG stream from (seed, doc_id), so
adding documents never rewrites existing ones.
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_SEED = 20260912
DEFAULT_PER_TYPE = 20
DEFAULT_NEGATIVES_PER_TYPE = 5

# --- fabricated name pools -------------------------------------------------

_SURNAMES = (
    "张", "王", "李", "赵", "刘", "陈", "杨", "黄", "周", "吴",
    "徐", "孙", "马", "朱", "胡", "郭", "何", "林", "罗", "高",
)
_GIVEN_NAMES = (
    "伟", "芳", "娜", "敏", "静", "磊", "军", "洋", "勇", "艳",
    "杰", "娟", "涛", "明", "超", "秀兰", "桂英", "玉梅", "建国", "淑芬",
    "海燕", "文博", "思远", "雅静",
)

# --- fabricated contact / network identifiers ------------------------------

_MOBILE_PREFIX = "138000"  # placeholder prefix used by README examples
_EMAIL_DOMAINS = ("example.com", "example.org")
_URL_HOSTS = ("example.org", "example.com")
_TEST_NET_BLOCKS = ("192.0.2", "198.51.100")  # RFC 5737
_ADDRESS_AREAS = (
    "北京市朝阳区", "上海市徐汇区", "深圳市福田区", "杭州市西湖区",
    "成都市武侯区", "武汉市江岸区", "南京市玄武区", "西安市新城区",
)
_ADDRESS_STREETS = ("幸福路", "康宁街", "梧桐巷", "柳林路", "和平街", "振兴路")
_ADDRESS_DETAILS = ("12号院3号楼502室", "88号1单元601室", "23号", "56号院2号楼", "7号3单元")

# --- organizations (institution-specific identity, no real hospitals) ------

_HOSPITALS = ("示例医院", "示范医院", "康宁医院", "和谐医院", "仁和医院")

# --- department taxonomy ---------------------------------------------------
# key -> (chief complaints, diagnoses, procedure/exam items)
# Departments are grouped the way real notes are: internal medicine, surgery,
# medical-technology (lab / imaging) and critical care.

_DEPARTMENTS: dict[str, dict[str, tuple[str, ...]]] = {
    "神经内科": {
        "complaints": (
            "因突发右侧肢体无力伴言语含糊2小时入院",
            "因反复头痛3个月加重1周入院",
            "因发作性意识丧失伴肢体抽搐1次入院",
        ),
        "diagnoses": ("脑梗死", "短暂性脑缺血发作", "偏头痛", "癫痫"),
    },
    "心内科": {
        "complaints": (
            "因活动后胸闷气促1月余入院",
            "因反复心悸2年加重3天入院",
            "因阵发性胸痛1周入院",
        ),
        "diagnoses": ("原发性高血压", "稳定型心绞痛", "心律失常", "慢性心力衰竭"),
    },
    "呼吸内科": {
        "complaints": (
            "因发热咳嗽咳痰5天入院",
            "因反复喘息3年加重2天入院",
            "因咳嗽伴痰中带血1周入院",
        ),
        "diagnoses": ("社区获得性肺炎", "慢性支气管炎急性发作", "支气管哮喘"),
    },
    "消化内科": {
        "complaints": (
            "因上腹隐痛伴反酸2月余入院",
            "因间断腹泻1月入院",
            "因进食后腹胀嗳气3周入院",
        ),
        "diagnoses": ("慢性胃炎", "胃食管反流病", "肠易激综合征"),
    },
    "内分泌科": {
        "complaints": (
            "因多饮多尿消瘦3月入院",
            "因乏力怕冷2月入院",
            "因体检发现血糖升高1周入院",
        ),
        "diagnoses": ("2型糖尿病", "甲状腺功能减退症", "高脂血症"),
    },
    "肾内科": {
        "complaints": (
            "因双下肢水肿伴尿量减少2周入院",
            "因泡沫尿1月入院",
            "因腰酸伴排尿不适3天入院",
        ),
        "diagnoses": ("慢性肾小球肾炎", "泌尿系感染", "肾病综合征"),
    },
    "血液科": {
        "complaints": (
            "因头晕乏力面色苍白2月入院",
            "因皮肤瘀点瘀斑1周入院",
            "因反复发热伴淋巴结肿大半月入院",
        ),
        "diagnoses": ("缺铁性贫血", "免疫性血小板减少症"),
    },
    "普通外科": {
        "complaints": (
            "因转移性右下腹痛12小时入院",
            "因发现腹股沟区可复性包块1年入院",
            "因右上腹疼痛伴发热1天入院",
        ),
        "diagnoses": ("急性阑尾炎", "腹股沟疝", "急性胆囊炎"),
    },
    "骨科": {
        "complaints": (
            "因摔伤致右腕疼痛畸形2小时入院",
            "因腰痛伴右下肢放射痛3月入院",
            "因跌倒致左髋疼痛不能站立1天入院",
        ),
        "diagnoses": ("右桡骨远端骨折", "腰椎间盘突出症", "左股骨颈骨折"),
    },
    "泌尿外科": {
        "complaints": (
            "因突发左侧腰部绞痛伴血尿6小时入院",
            "因排尿困难进行性加重1年入院",
            "因体检发现肾结石2周入院",
        ),
        "diagnoses": ("泌尿系结石", "良性前列腺增生", "肾结石"),
    },
    "重症医学科": {
        "complaints": (
            "因高热寒战伴呼吸困难1天由急诊转入",
            "因意识障碍伴血压下降6小时转入",
            "因术后呼吸衰竭转入监护治疗",
        ),
        "diagnoses": ("重症肺炎", "脓毒性休克", "急性呼吸窘迫综合征"),
    },
    "急诊科": {
        "complaints": (
            "因进食不洁食物后呕吐腹泻4小时就诊",
            "因突发头晕伴恶心2小时就诊",
            "因猫抓伤后右手红肿1天就诊",
        ),
        "diagnoses": ("急性胃肠炎", "眩晕综合征", "右手软组织感染"),
    },
    "检验科": {
        "complaints": ("因常规复查就诊", "因术前检查就诊", "因发热待查就诊"),
        "diagnoses": ("血常规异常待查", "肝功能异常待查", "电解质紊乱"),
    },
    "影像科": {
        "complaints": ("因头痛行头颅检查", "因胸痛行胸部检查", "因腹痛行腹部检查"),
        "diagnoses": ("颅内未见明显异常", "双肺纹理增粗", "肝胆胰脾未见明显异常"),
    },
}

# Imaging/lab procedure names keyed loosely to department groups.
_IMAGING_ITEMS = (
    "头颅MRI平扫", "胸部CT平扫", "腹部超声", "腰椎MRI", "心脏彩超",
    "泌尿系CT", "膝关节正侧位X线", "颈部血管超声",
)
_LAB_ITEMS = (
    "血常规", "尿常规", "肝功能", "肾功能", "电解质", "凝血功能",
    "空腹血糖", "糖化血红蛋白", "甲状腺功能", "C反应蛋白",
)
_OPERATIONS = (
    "腹腔镜阑尾切除术", "桡骨远端骨折切开复位内固定术", "经尿道输尿管镜碎石取石术",
    "腹腔镜胆囊切除术", "无张力疝修补术", "全髋关节置换术",
)
_MEDICATIONS = (
    "阿司匹林肠溶片", "阿托伐他汀钙片", "硝苯地平控释片", "二甲双胍缓释片",
    "头孢呋辛钠", "氯化钾缓释片", "布洛芬缓释胶囊",
)
_ALLERGIES = ("否认药物及食物过敏史", "青霉素过敏", "磺胺类药物过敏")
_PAST_HISTORY = (
    "既往体健，否认高血压、糖尿病病史",
    "既往高血压病史10年，规律服药",
    "既往2型糖尿病病史5年，口服降糖药治疗",
    "既往脑梗死病史，遗留左侧肢体活动不便",
)
_MARITAL = ("已婚", "未婚", "离异")
_OCCUPATIONS = ("退休", "职员", "农民", "教师", "自由职业", "学生")


# --- span recording builder ------------------------------------------------


@dataclass
class NoteBuilder:
    """Assembles a note from segments while recording PHI spans.

    Spans are recorded in ``DetectedFact`` offset space: Python code-point
    indices into the assembled text (identical to what ``re.finditer`` and the
    detectors report).
    """

    parts: list[str] = field(default_factory=list)
    spans: list[dict] = field(default_factory=list)
    _pos: int = 0

    def add(self, text: str, phi_type: str | None = None) -> "NoteBuilder":
        if phi_type and text:
            self.spans.append(
                {"type": phi_type, "start": self._pos, "end": self._pos + len(text)}
            )
        self.parts.append(text)
        self._pos += len(text)
        return self

    def line(self, text: str = "") -> "NoteBuilder":
        """Append a segment and a newline."""
        return self.add(text + "\n")

    def phi(self, text: str, phi_type: str) -> "NoteBuilder":
        """Append a PHI segment with an explicit type."""
        return self.add(text, phi_type)

    def text(self) -> str:
        return "".join(self.parts)


# --- identifier factories --------------------------------------------------

_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CHECK_MAP = "10X98765432"
_ID_REGIONS = ("110105", "310104", "440304", "330106", "510107", "420102", "320102", "610102")


def make_resident_id(rng: random.Random) -> tuple[str, int]:
    """Return (id18, birth_year) for a fabricated resident ID.

    Uses a real administrative prefix and a fabricated birth date/sequence,
    then computes the GB 11643-1999 check digit so the value exercises the
    detector's check-digit validation path.
    """
    region = rng.choice(_ID_REGIONS)
    year = rng.randint(1940, 2005)
    month = rng.randint(1, 12)
    day = rng.randint(1, 28)
    seq = f"{rng.randint(0, 999):03d}"
    body = f"{region}{year:04d}{month:02d}{day:02d}{seq}"
    total = sum(int(d) * w for d, w in zip(body, _ID_WEIGHTS))
    return body + _ID_CHECK_MAP[total % 11], year


def make_mobile(rng: random.Random) -> str:
    """Fabricated 11-digit mobile number using the README placeholder prefix."""
    return f"{_MOBILE_PREFIX}{rng.randint(0, 99999):05d}"


def make_date(rng: random.Random, chinese: bool = False) -> str:
    """Fabricated date inside 2026, ISO or Chinese format."""
    month = rng.randint(1, 12)
    day = rng.randint(1, 28)
    if chinese:
        return f"2026年{month}月{day}日"
    return f"2026-{month:02d}-{day:02d}"


def add_date(builder: "NoteBuilder", rng: random.Random, with_phi: bool) -> None:
    """Append a date field.

    In no-direct-identifier documents the date is reduced to month granularity
    so the note carries no EXACT_DATE span and exercises the ASK path.
    """
    if with_phi:
        builder.phi(make_date(rng), "EXACT_DATE")
    else:
        builder.add(f"2026年{rng.randint(1, 12)}月")


def make_address(rng: random.Random) -> str:
    return f"{rng.choice(_ADDRESS_AREAS)}{rng.choice(_ADDRESS_STREETS)}{rng.choice(_ADDRESS_DETAILS)}"


def make_person(rng: random.Random) -> str:
    return rng.choice(_SURNAMES) + rng.choice(_GIVEN_NAMES)


def make_mrn(rng: random.Random, prefix: str = "ZY") -> str:
    return f"{prefix}2026{rng.randint(1, 9999):04d}"


def make_email(rng: random.Random) -> str:
    return f"synth{rng.randint(1, 9999):04d}@{rng.choice(_EMAIL_DOMAINS)}"


def make_url(rng: random.Random) -> str:
    return f"https://{rng.choice(_URL_HOSTS)}/report/{make_mrn(rng, 'IMG')}"


def make_ip(rng: random.Random) -> str:
    return f"{rng.choice(_TEST_NET_BLOCKS)}.{rng.randint(10, 250)}"


# Landline uses the reserved 010/021/0755-style area codes with fabricated
# local numbers; area codes are public, the numbers are invented.
_LANDLINE_AREA_CODES = ("010", "021", "022", "025", "027", "028", "0755", "0757")


def make_landline(rng: random.Random) -> str:
    return f"{rng.choice(_LANDLINE_AREA_CODES)}-{rng.randint(60000000, 89999999)}"


def make_postal_code(rng: random.Random) -> str:
    return f"{rng.randint(100000, 999999)}"


def make_social_id(rng: random.Random) -> str:
    return f"patient_{rng.randint(1000, 9999)}"


def make_specimen_id(rng: random.Random) -> str:
    return f"SP{rng.randint(100000, 999999)}"


def make_accession_id(rng: random.Random) -> str:
    return f"IM{rng.randint(1000000, 9999999)}"


def add_relative_line(builder: "NoteBuilder", rng: random.Random) -> None:
    """Append a family-member sentence with the relative's name spanned."""
    kind = rng.choice(("其妻", "其夫", "父亲", "母亲", "儿子", "女儿"))
    builder.add(f"陪同人员：{kind}")
    builder.phi(make_person(rng), "RELATIVE_NAME")
    builder.line("陪同就诊。")


def add_rare_context(builder: "NoteBuilder", rng: random.Random) -> None:
    """Append a narrative re-identification phrase.

    The spanned text is exactly the phrase the detector reports, so span
    alignment stays precise rather than relying on generous overlap.
    """
    prefix = rng.choice(("本例为", "该病例为", "本患者为"))
    phrase = rng.choice(("本县唯一", "本市唯一", "国内首例", "罕见变异型病例"))
    builder.add(prefix)
    builder.phi(phrase, "RARE_CONTEXT")
    builder.line("，已按疑难病例上报。")


def age_from_birth_year(birth_year: int) -> int:
    return max(0, 2026 - birth_year)


# --- shared narrative fragments -------------------------------------------


def _vitals(rng: random.Random) -> str:
    return (
        f"体温{rng.randint(36, 39)}.{rng.randint(0, 9)}℃，"
        f"脉搏{rng.randint(60, 110)}次/分，"
        f"血压{rng.randint(100, 165)}/{rng.randint(60, 100)}mmHg，"
        f"呼吸{rng.randint(14, 24)}次/分"
    )


def _lab_results(rng: random.Random, items: int = 3) -> list[str]:
    picked = rng.sample(_LAB_ITEMS, k=min(items, len(_LAB_ITEMS)))
    lines = []
    for item in picked:
        lines.append(
            f"{item}：" + rng.choice(
                ("大致正常", "轻度升高", "轻度降低", "未见明显异常", "较前改善")
            )
        )
    return lines


# --- document builders (7 types) ------------------------------------------


# --- identifier-free documents (negative corpus) ---------------------------
#
# These documents carry clinical content but no identifier of any kind: no
# name, age, sex, date, number, address, institution or staff name. Every
# span-level fact detected in one is therefore a false positive by
# construction, which is what makes over-redaction measurable at all.
#
# The templates deliberately include "near miss" phrases that look like
# identifiers but are not: 男病房 is a room rather than a patient, 共12名医生
# is a headcount rather than a name, 主任医师 and 责任护士 are titles,
# 床位紧张 is a concept, and a bare 6-digit run is a dose rather than a
# postal code. A detector that fires on these silently strips clinical
# meaning out of released text, which is the failure mode this corpus exists
# to catch.

_NEGATIVE_TITLES: dict[str, str] = {
    "outpatient_note": "门诊病历",
    "inpatient_progress": "住院病程记录",
    "discharge_summary": "出院小结",
    "imaging_report": "影像检查报告单",
    "lab_report": "检验报告单",
    "operation_note": "手术记录",
    "consultation_note": "会诊记录",
}

_NEGATIVE_NEAR_MISS: tuple[str, ...] = (
    "本病区实行男病房与女病房分区管理。",
    "各科病区落实交接班制度。",
    "全病区开展应急演练。",
    "入组人群的男女比例约为1:1。",
    "该研究纳入男性与女性受试者各半。",
    "本科室共12名医生，护理人员按班次轮转。",
    "主任医师每周查房两次，主治医师每日查房。",
    "责任护士每班交接，护理记录完整。",
    "住院医师规范化培训按期完成。",
    "护理人员按职称分级管理。",
    "近期床位紧张，需协调周转。",
    "病区消杀记录齐全，管理规范。",
    "本科室学科建设良好，外科手术流程规范。",
    "医院管理规范要求加强病历质量管理。",
    "该院为三级甲等医院。",
    "转诊至上级医院进一步诊治。",
    "建议转当地医院继续治疗。",
    "该病多见于50岁以上人群。",
    "本研究纳入18岁以上成人。",
    "加强罕见病诊疗管理。",
    "完善罕见病病例登记。",
    "建议神经内科会诊协助诊治。",
    "住院6天，费用1200元。",
    "术中出血约200ml，输血400ml。",
    "剂量120000单位，参考范围3.5-5.5。",
    "每日3次口服，每次2片。",
    "血压控制在130/80mmHg左右。",
    "该病例已按常规流程处理。",
    "本例按标准方案治疗，疗效可。",
    "建议相关科室随诊，必要时复诊。",
)

_NEGATIVE_CLOSING: tuple[str, ...] = (
    "继续观察病情变化，必要时复查相关指标。",
    "注意监测生命体征，警惕病情进展。",
    "与家属沟通病情，表示理解并配合治疗。",
    "宣教完毕，患者表示知晓。",
)


def _build_negative(doc_type: str, rng: random.Random, dept: str) -> NoteBuilder:
    """Build one identifier-free document of ``doc_type``.

    These exercise the ASK path — clinical content with no direct identifier
    must be escalated rather than released to an unknown external recipient —
    and they are the only place the benchmark can observe a false positive,
    since a positive document can always explain a hit with a label.
    """
    spec = _DEPARTMENTS[dept]
    complaint = rng.choice(spec["complaints"])
    diagnosis = rng.choice(spec["diagnoses"])
    vitals = _vitals(rng)
    lab = rng.choice(_LAB_ITEMS)
    med = rng.choice(_MEDICATIONS)
    imaging = rng.choice(_IMAGING_ITEMS)
    operation = rng.choice(_OPERATIONS)
    history = rng.choice(_PAST_HISTORY)
    title = _NEGATIVE_TITLES[doc_type]

    if doc_type == "outpatient_note":
        body = (
            f"主诉：{complaint}",
            f"现病史：{history}，近{rng.randint(1, 10)}天症状反复。",
            f"过敏史：{rng.choice(_ALLERGIES)}",
            f"体格检查：{vitals}",
            f"辅助检查：{lab}提示轻度异常。",
            f"诊断：{diagnosis}",
            f"处理：{med}，每日{rng.randint(1, 3)}次口服，{rng.randint(1, 4)}周后复查。",
        )
    elif doc_type == "inpatient_progress":
        body = (
            f"主诉：{complaint}",
            f"今日查房：患者神志清楚，{vitals}。",
            f"症状较前{rng.choice(('好转', '无明显变化', '减轻'))}，饮食睡眠可，二便正常。",
            f"辅助检查回报：{lab}示{rng.choice(('轻度异常', '大致正常', '较前改善'))}。",
            f"诊断：{diagnosis}",
            f"治疗：{med}口服，继续观察病情变化。",
        )
    elif doc_type == "discharge_summary":
        body = (
            f"入院情况：患者{complaint}。",
            f"诊疗经过：入院后完善相关检查，予{med}等治疗，症状{rng.choice(('明显好转', '好转', '缓解'))}。",
            f"出院诊断：{diagnosis}",
            f"出院情况：{vitals}，一般情况可。",
            f"出院医嘱：{med}继续口服{rng.randint(1, 4)}周；{rng.randint(1, 4)}周后门诊复查。",
        )
    elif doc_type == "imaging_report":
        body = (
            f"检查项目：{imaging}",
            f"检查所见：{rng.choice(('未见明显异常信号影', '可见斑片状稍长T2信号', '双肺纹理增粗'))}，"
            f"其余结构形态信号{rng.choice(('未见异常', '大致正常'))}。",
            f"印象（诊断倾向）：{diagnosis}可能，建议结合临床。",
        )
    elif doc_type == "lab_report":
        body = (
            f"检验项目：{lab}",
            f"结果：{lab}{rng.choice(('轻度升高', '轻度降低', '未见异常'))}，其余指标未见明显异常。",
            f"结论：{diagnosis}相关指标{rng.choice(('大致正常', '轻度异常'))}，建议复查。",
        )
    elif doc_type == "operation_note":
        body = (
            f"术前诊断：{diagnosis}",
            f"手术名称：{operation}",
            f"麻醉方式：{rng.choice(('全身麻醉', '椎管内麻醉', '局部浸润麻醉'))}",
            f"术中情况：手术顺利，出血约{rng.randint(20, 300)}ml，术毕安返病房。",
            f"术后医嘱：{med}，{rng.choice(('禁食6小时后改流质', '平卧6小时', '监测生命体征'))}。",
        )
    else:  # consultation_note
        body = (
            f"会诊目的：协助诊治{diagnosis}。",
            f"会诊意见：结合病史及辅助检查，考虑{diagnosis}，"
            f"建议完善{lab}及{imaging}，可予{med}治疗。",
            "建议相关科室随诊，必要时复诊。",
        )

    near_miss = rng.sample(_NEGATIVE_NEAR_MISS, k=3)
    closing = rng.choice(_NEGATIVE_CLOSING)

    b = NoteBuilder()
    b.line(title)
    for line in body:
        b.line(line)
    for line in near_miss:
        b.line(line)
    b.line(closing)
    return b


def build_outpatient_note(rng: random.Random, dept: str, with_phi: bool) -> NoteBuilder:
    if not with_phi:
        return _build_negative("outpatient_note", rng, dept)
    b = NoteBuilder()
    spec = _DEPARTMENTS[dept]
    b.line("门诊病历")
    b.add("医院名称：")
    b.phi(rng.choice(_HOSPITALS), "HOSPITAL_NAME")
    b.line()
    b.add("就诊日期：")
    add_date(b, rng, with_phi)
    b.line()
    b.add("就诊科室：")
    b.phi(dept, "DEPARTMENT")
    b.line()

    if with_phi:
        name = make_person(rng)
        b.add("患者姓名：")
        b.phi(name, "PERSON_NAME")
        b.add("，性别：")
        b.phi(rng.choice(("男", "女")), "SEX")
        b.add("，年龄：")
        b.phi(f"{rng.randint(18, 88)}岁", "AGE")
        b.line()
        b.add("联系电话：")
        b.phi(make_mobile(rng), "PHONE")
        b.line()
        if rng.random() < 0.6:
            b.add("家庭住址：")
            b.phi(make_address(rng), "PRECISE_LOCATION")
            b.line()
        if rng.random() < 0.35:
            b.add("电子邮箱：")
            b.phi(make_email(rng), "EMAIL")
            b.line()
        if rng.random() < 0.3:
            id18, _ = make_resident_id(rng)
            b.add("身份证号：")
            b.phi(id18, "GOVERNMENT_ID")
            b.line()
        if rng.random() < 0.4:
            b.add("固定电话：")
            b.phi(make_landline(rng), "LANDLINE")
            b.line()
        if rng.random() < 0.35:
            b.add("邮政编码：")
            b.phi(make_postal_code(rng), "POSTAL_CODE")
            b.line()
        if rng.random() < 0.3:
            b.add("微信号：")
            b.phi(make_social_id(rng), "SOCIAL_MEDIA_ID")
            b.line()
        b.add("门诊号：")
        b.phi(make_mrn(rng, "MZ"), "MEDICAL_RECORD_NUMBER")
        b.line()
    else:
        b.line("成年患者，具体年龄与性别见病案首页。")

    b.line(f"主诉：{rng.choice(spec['complaints'])}")
    b.line(f"现病史：{rng.choice(_PAST_HISTORY)}，近{rng.randint(1, 10)}天症状反复。")
    b.line(f"过敏史：{rng.choice(_ALLERGIES)}")
    b.line(f"体格检查：{_vitals(rng)}")
    b.line(f"辅助检查：{rng.choice(_LAB_ITEMS)}提示轻度异常。")
    b.line(f"诊断：{rng.choice(spec['diagnoses'])}")
    b.line(f"用药：{rng.choice(_MEDICATIONS)}，每日{rng.randint(1, 3)}次口服。")
    b.line(f"处理：建议{rng.randint(1, 4)}周后门诊复查，不适随诊。")
    if with_phi and rng.random() < 0.25:
        add_relative_line(b, rng)
    if with_phi and rng.random() < 0.15:
        add_rare_context(b, rng)
    b.add("接诊医师：")
    b.phi(make_person(rng), "DOCTOR_NAME")
    b.line("医生")
    if with_phi and rng.random() < 0.3:
        b.add("随访链接：")
        b.phi(make_url(rng), "URL")
        b.line()
    return b


def build_inpatient_progress(rng: random.Random, dept: str, with_phi: bool) -> NoteBuilder:
    if not with_phi:
        return _build_negative("inpatient_progress", rng, dept)
    b = NoteBuilder()
    spec = _DEPARTMENTS[dept]
    b.line("住院病程记录")
    b.add("记录日期：")
    add_date(b, rng, with_phi)
    b.line()
    b.add("科室：")
    b.phi(dept, "DEPARTMENT")
    b.line()

    if with_phi:
        b.add("患者：")
        b.phi(make_person(rng), "PERSON_NAME")
        b.add("，性别：")
        b.phi(rng.choice(("男", "女")), "SEX")
        b.add("，住院号：")
        b.phi(make_mrn(rng), "MEDICAL_RECORD_NUMBER")
        b.line()
        if rng.random() < 0.35:
            b.add("联系电话：")
            b.phi(make_mobile(rng), "PHONE")
            b.line()
    else:
        b.line("患者，住院号已脱敏记录")

    b.add("床号：")
    b.phi(f"{rng.randint(1, 60)}床", "BED_NUMBER")
    b.add("，")
    b.phi(f"{rng.choice(('一', '二', '三', '四'))}病区", "WARD")
    b.add("，年龄：")
    b.phi(f"{rng.randint(18, 90)}岁", "AGE")
    b.line()

    b.add("入院日期：")
    add_date(b, rng, with_phi)
    b.line()
    b.line(f"主诉：{rng.choice(spec['complaints'])}")
    b.line(f"今日查房：患者神志清楚，精神可，{_vitals(rng)}。")
    b.line(f"症状较前{rng.choice(('好转', '无明显变化', '加重'))}，饮食睡眠可，二便正常。")
    b.line(f"辅助检查回报：{rng.choice(_LAB_ITEMS)}示{rng.choice(('轻度异常', '大致正常', '较前改善'))}。")
    b.line(f"诊断：{rng.choice(spec['diagnoses'])}")
    b.line(f"治疗：{rng.choice(_MEDICATIONS)}口服，继续观察病情变化。")
    b.line(f"上级医师查房意见：同意当前诊疗方案，注意监测{rng.choice(('血压', '血糖', '肝肾功能', '电解质'))}。")
    b.add("查房医师签名：")
    b.phi(make_person(rng), "DOCTOR_NAME")
    b.line("医生")
    b.add("责任护士：")
    b.phi(make_person(rng), "NURSE_NAME")
    b.line("护士")
    return b


def build_discharge_summary(rng: random.Random, dept: str, with_phi: bool) -> NoteBuilder:
    if not with_phi:
        return _build_negative("discharge_summary", rng, dept)
    b = NoteBuilder()
    spec = _DEPARTMENTS[dept]
    b.line("出院小结")
    b.add("入院日期：")
    add_date(b, rng, with_phi)
    b.add("　　出院日期：")
    add_date(b, rng, with_phi)
    b.line()
    b.add("科室：")
    b.phi(dept, "DEPARTMENT")
    b.add("，医院名称：")
    b.phi(rng.choice(_HOSPITALS), "HOSPITAL_NAME")
    b.add("，")
    b.phi(f"{rng.choice(('一', '二', '三', '四'))}病区", "WARD")
    b.line()

    if with_phi:
        b.add("患者姓名：")
        b.phi(make_person(rng), "PERSON_NAME")
        b.add("，性别：")
        b.phi(rng.choice(("男", "女")), "SEX")
        b.add("，住院号：")
        b.phi(make_mrn(rng), "MEDICAL_RECORD_NUMBER")
        b.line()
        b.add("年龄：")
        b.phi(f"{rng.randint(18, 90)}岁", "AGE")
        b.line()
        if rng.random() < 0.5:
            b.add("联系地址：")
            b.phi(make_address(rng), "PRECISE_LOCATION")
            b.line()
        if rng.random() < 0.4:
            b.add("联系电话：")
            b.phi(make_mobile(rng), "PHONE")
            b.line()
        if rng.random() < 0.3:
            b.add("检查号：")
            b.phi(make_accession_id(rng), "ACCESSION_NUMBER")
            b.line()
    else:
        b.line("成年患者，具体年龄与性别见病案首页。")
        b.line("患者姓名与住院号见病案首页")

    b.line(f"入院诊断：{rng.choice(spec['diagnoses'])}")
    b.line(f"出院诊断：{rng.choice(spec['diagnoses'])}")
    b.line(f"住院经过：患者{rng.choice(spec['complaints'])}，入院后完善相关检查，予{rng.choice(_MEDICATIONS)}等治疗，症状{rng.choice(('明显好转', '好转', '缓解'))}。")
    b.line(f"出院情况：{_vitals(rng)}，一般情况可。")
    b.line(f"出院医嘱：{rng.choice(_MEDICATIONS)}继续口服{rng.randint(1, 4)}周；{rng.randint(1, 4)}周后门诊复查；如有不适及时就诊。")
    if with_phi and rng.random() < 0.25:
        b.add("复查预约：")
        b.phi(make_url(rng), "URL")
        b.line()
    b.add("经治医师：")
    b.phi(make_person(rng), "DOCTOR_NAME")
    b.line("医生")
    return b


def _requesting_department(rng: random.Random, dept: str) -> str:
    """Return a plausible requesting department.

    A medical-technology department (lab / imaging) never requests its own
    service, so such documents name a clinical department as the requester.
    """
    if dept in _TECHNOLOGY_DEPARTMENTS:
        return rng.choice(_CLINICAL_DEPARTMENTS)
    return dept


def build_imaging_report(rng: random.Random, dept: str, with_phi: bool) -> NoteBuilder:
    if not with_phi:
        return _build_negative("imaging_report", rng, dept)
    b = NoteBuilder()
    b.line("影像检查报告单")
    b.add("检查日期：")
    add_date(b, rng, with_phi)
    b.line()
    b.add("检查科室：")
    b.phi("影像科", "DEPARTMENT")
    b.add("，申请科室：")
    b.phi(_requesting_department(rng, dept), "DEPARTMENT")
    b.line()

    if with_phi:
        b.add("患者姓名：")
        b.phi(make_person(rng), "PERSON_NAME")
        b.add("，性别：")
        b.phi(rng.choice(("男", "女")), "SEX")
        b.add("，年龄：")
        b.phi(f"{rng.randint(18, 85)}岁", "AGE")
        b.line()
        b.add("门诊号：")
        b.phi(make_mrn(rng, "MZ"), "MEDICAL_RECORD_NUMBER")
        b.line()
        b.add("检查号：")
        b.phi(make_accession_id(rng), "ACCESSION_NUMBER")
        b.line()
    else:
        b.line("成年患者，具体年龄与性别见病案首页。")
        b.line("患者信息参见申请单")

    b.line(f"检查项目：{rng.choice(_IMAGING_ITEMS)}")
    b.line(f"检查结果所见：{rng.choice(('未见明显异常信号影', '可见斑片状稍长T2信号', '双肺纹理增粗', '局部骨质连续性中断'))}，"
           f"其余结构形态信号{rng.choice(('未见异常', '大致正常'))}。")
    b.line(f"印象（诊断倾向）：{rng.choice(_DEPARTMENTS[dept]['diagnoses'])}可能，建议结合临床。")
    b.add("报告医师：")
    b.phi(make_person(rng), "DOCTOR_NAME")
    b.add("医生　　审核医师：")
    b.phi(make_person(rng), "DOCTOR_NAME")
    b.line("医生")
    if with_phi and rng.random() < 0.3:
        b.add("影像已上传院内系统：")
        b.phi(make_ip(rng), "IP_ADDRESS")
        b.line()
    return b


def build_lab_report(rng: random.Random, dept: str, with_phi: bool) -> NoteBuilder:
    if not with_phi:
        return _build_negative("lab_report", rng, dept)
    b = NoteBuilder()
    b.line("检验报告单")
    b.add("采样日期：")
    add_date(b, rng, with_phi)
    b.line()
    b.add("检验部门：")
    b.phi("检验科", "DEPARTMENT")
    b.add("，申请科室：")
    b.phi(_requesting_department(rng, dept), "DEPARTMENT")
    b.line()

    if with_phi:
        b.add("患者：")
        b.phi(make_person(rng), "PERSON_NAME")
        b.add("，性别：")
        b.phi(rng.choice(("男", "女")), "SEX")
        b.add("，病案号：")
        b.phi(make_mrn(rng), "MEDICAL_RECORD_NUMBER")
        b.line()
        b.add("年龄：")
        b.phi(f"{rng.randint(18, 90)}岁", "AGE")
        b.line()
        if rng.random() < 0.3:
            id18, _ = make_resident_id(rng)
            b.add("身份证号：")
            b.phi(id18, "GOVERNMENT_ID")
            b.line()
        if rng.random() < 0.3:
            b.add("邮政编码：")
            b.phi(make_postal_code(rng), "POSTAL_CODE")
            b.line()
    else:
        b.line("成年患者，具体年龄与性别见病案首页。")
        b.line("患者信息以条码为准")

    b.add("标本号：")
    b.phi(make_specimen_id(rng), "SPECIMEN_ID")
    b.line()
    for item in rng.sample(_LAB_ITEMS, k=3):
        b.line(f"{item}：{rng.choice(('正常', '轻度升高', '轻度降低', '未见异常'))}")
    b.line(f"检验结论：{rng.choice(_DEPARTMENTS[dept]['diagnoses'])}相关指标{rng.choice(('大致正常', '轻度异常'))}，建议复查。")
    b.add("检验医师：")
    b.phi(make_person(rng), "DOCTOR_NAME")
    b.add("医生　　报告日期：")
    add_date(b, rng, with_phi)
    b.line()
    return b


def build_operation_note(rng: random.Random, dept: str, with_phi: bool) -> NoteBuilder:
    if not with_phi:
        return _build_negative("operation_note", rng, dept)
    b = NoteBuilder()
    spec = _DEPARTMENTS[dept]
    b.line("手术记录")
    b.add("手术日期：")
    add_date(b, rng, with_phi)
    b.line()
    b.add("手术科室：")
    b.phi(dept, "DEPARTMENT")
    b.line()

    if with_phi:
        b.add("患者姓名：")
        b.phi(make_person(rng), "PERSON_NAME")
        b.add("，性别：")
        b.phi(rng.choice(("男", "女")), "SEX")
        b.add("，住院号：")
        b.phi(make_mrn(rng), "MEDICAL_RECORD_NUMBER")
        b.line()
        b.add("年龄：")
        b.phi(f"{rng.randint(18, 90)}岁", "AGE")
        b.line()
        if rng.random() < 0.3:
            b.add("检查号：")
            b.phi(make_accession_id(rng), "ACCESSION_NUMBER")
            b.line()
    else:
        b.line("成年患者，具体年龄与性别见病案首页。")
        b.line("患者身份信息见手术安全核查表")

    b.line(f"术前诊断：{rng.choice(spec['diagnoses'])}")
    b.line(f"手术名称：{rng.choice(_OPERATIONS)}")
    b.line(f"麻醉方式：{rng.choice(('全身麻醉', '椎管内麻醉', '局部浸润麻醉'))}")
    b.line(f"术中情况：{rng.choice(('手术顺利', '术中出血约' + str(rng.randint(20, 300)) + 'ml', '手术顺利，麻醉满意'))}，"
           f"术毕安返病房。")
    b.line(f"术后医嘱：{rng.choice(_MEDICATIONS)}，{rng.choice(('禁食6小时后改流质', '平卧6小时', '监测生命体征'))}。")
    b.add("手术医师：")
    b.phi(make_person(rng), "DOCTOR_NAME")
    b.add("医生　　助手：")
    b.phi(make_person(rng), "DOCTOR_NAME")
    b.line("医生")
    b.add("巡回护士：")
    b.phi(make_person(rng), "NURSE_NAME")
    b.line("护士")
    return b


def build_consultation_note(rng: random.Random, dept: str, with_phi: bool) -> NoteBuilder:
    if not with_phi:
        return _build_negative("consultation_note", rng, dept)
    b = NoteBuilder()
    b.line("会诊记录")
    b.add("会诊日期：")
    add_date(b, rng, with_phi)
    b.line()
    b.add("邀请科室：")
    b.phi(dept, "DEPARTMENT")
    b.add("，会诊科室：")
    b.phi(rng.choice(("神经内科", "心内科", "内分泌科")), "DEPARTMENT")
    b.line()

    if with_phi:
        b.add("患者：")
        b.phi(make_person(rng), "PERSON_NAME")
        b.add("，性别：")
        b.phi(rng.choice(("男", "女")), "SEX")
        b.add("，住院号：")
        b.phi(make_mrn(rng), "MEDICAL_RECORD_NUMBER")
        b.line()
        b.add("年龄：")
        b.phi(f"{rng.randint(18, 90)}岁", "AGE")
        b.line()
        if rng.random() < 0.3:
            b.add("联系电话：")
            b.phi(make_mobile(rng), "PHONE")
            b.line()
        if rng.random() < 0.25:
            add_relative_line(b, rng)
        if rng.random() < 0.15:
            add_rare_context(b, rng)
    else:
        b.line("成年患者，具体年龄与性别见病案首页。")
        b.line("患者信息见会诊申请单")

    b.line(f"会诊目的：协助诊治{rng.choice(_DEPARTMENTS[dept]['diagnoses'])}。")
    b.line(f"会诊意见：结合病史及辅助检查，考虑{rng.choice(_DEPARTMENTS[dept]['diagnoses'])}，"
           f"建议完善{rng.choice(_LAB_ITEMS)}及{rng.choice(_IMAGING_ITEMS)}，"
           f"可予{rng.choice(_MEDICATIONS)}治疗，必要时复诊。")
    b.add("会诊医师：")
    b.phi(make_person(rng), "DOCTOR_NAME")
    b.line("医生")
    return b


_BUILDERS = {
    "outpatient_note": build_outpatient_note,
    "inpatient_progress": build_inpatient_progress,
    "discharge_summary": build_discharge_summary,
    "imaging_report": build_imaging_report,
    "lab_report": build_lab_report,
    "operation_note": build_operation_note,
    "consultation_note": build_consultation_note,
}

# Departments that can plausibly issue each document type. Lab and imaging are
# medical-technology departments: they produce reports for other departments
# rather than admitting patients, so they never appear as the owning
# department on a discharge summary or operation note.
_TECHNOLOGY_DEPARTMENTS = frozenset({"检验科", "影像科"})
# sorted() throughout: tuple(frozenset) iterates in hash order, which varies
# with PYTHONHASHSEED, so an unsorted conversion would make the "byte-exact
# reproducibility" guarantee depend on the process that generated the corpus.
_TECHNOLOGY_DEPARTMENTS_ORDERED = tuple(sorted(_TECHNOLOGY_DEPARTMENTS))
_CLINICAL_DEPARTMENTS = tuple(sorted(set(_DEPARTMENTS) - _TECHNOLOGY_DEPARTMENTS))

_DEPARTMENTS_BY_DOC_TYPE: dict[str, tuple[str, ...]] = {
    "outpatient_note": _CLINICAL_DEPARTMENTS,
    "inpatient_progress": _CLINICAL_DEPARTMENTS,
    "discharge_summary": _CLINICAL_DEPARTMENTS,
    "operation_note": tuple(
        d
        for d in _CLINICAL_DEPARTMENTS
        if d in {"普通外科", "骨科", "泌尿外科", "神经内科", "心内科", "重症医学科"}
    ),
    "consultation_note": _CLINICAL_DEPARTMENTS,
    "imaging_report": _TECHNOLOGY_DEPARTMENTS_ORDERED + _CLINICAL_DEPARTMENTS,
    "lab_report": _TECHNOLOGY_DEPARTMENTS_ORDERED + _CLINICAL_DEPARTMENTS,
}

DOC_TYPES: tuple[str, ...] = tuple(_BUILDERS)


# --- corpus generation -----------------------------------------------------


def _expected_verdict(negative: bool, spans: list[dict]) -> str:
    """The verdict the corpus expects, as a rule about the document itself.

    Deliberately hand-written rather than obtained by running the guard: an
    expectation copied from the implementation would confirm whatever the
    implementation does, and could never fail.

    - identifier-free: nothing to redact, so a declared purpose is enough;
    - rare-context signal: a re-identification claim such as "本县唯一" cannot
      be made safe by rewriting a span, so external disclosure needs scoped
      human review;
    - otherwise: direct identifiers are present and must be transformed
      before the note leaves the boundary.
    """
    if negative:
        return "ALLOW"
    if any(span["type"] == "RARE_CONTEXT" for span in spans):
        return "ASK"
    return "SANITIZE"


def generate_document(
    doc_type: str, index: int, seed: int, negative: bool = False
) -> tuple[str, dict]:
    """Build one document deterministically from (seed, doc_type, index).

    ``negative`` selects the identifier-free form, which is the only place the
    benchmark can observe a false positive: a positive document can always
    explain a detected fact with a label, a negative one cannot.
    """
    doc_id = f"{doc_type}_neg_{index:03d}" if negative else f"{doc_type}_{index:03d}"
    rng = random.Random(f"{seed}:{doc_id}")

    # No fresh random draws before this point: deterministic per doc_id.
    # Department choices are constrained by the document type so the note
    # stays clinically plausible.
    dept = rng.choice(_DEPARTMENTS_BY_DOC_TYPE[doc_type])

    builder = _BUILDERS[doc_type](rng, dept, with_phi=not negative)
    text = builder.text()

    meta = {
        "doc_id": doc_id,
        "language": "zh-CN",
        "document_type": doc_type,
        "department": dept,
        "synthetic": True,
        "generator_seed": seed,
        "corpus_role": "negative" if negative else "positive",
        "spans": builder.spans,
        "expected_verdict": _expected_verdict(negative, builder.spans),
        "text_policy": "do_not_store_in_audit",
    }
    return text, meta


def generate_corpus(
    out_dir: Path,
    per_type: int = DEFAULT_PER_TYPE,
    negatives_per_type: int = DEFAULT_NEGATIVES_PER_TYPE,
    seed: int = DEFAULT_SEED,
) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    # Clear previously generated corpus files so stale documents cannot linger.
    for stale in list(out_dir.glob("*.txt")) + list(out_dir.glob("*.spans.json")):
        stale.unlink()

    written = 0
    for doc_type in DOC_TYPES:
        for negative in (False, True):
            count = negatives_per_type if negative else per_type
            for index in range(1, count + 1):
                text, meta = generate_document(doc_type, index, seed, negative=negative)
                base = out_dir / meta["doc_id"]
                base.with_suffix(".txt").write_text(text, encoding="utf-8")
                base.with_suffix(".spans.json").write_text(
                    json.dumps(meta, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
                written += 1
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="tests/fixtures/synthetic_cn_notes", help="output directory")
    parser.add_argument("--per-type", type=int, default=DEFAULT_PER_TYPE, help="documents per type")
    parser.add_argument(
        "--negatives-per-type",
        type=int,
        default=DEFAULT_NEGATIVES_PER_TYPE,
        help="identifier-free documents per type",
    )
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="deterministic seed")
    args = parser.parse_args(argv)

    count = generate_corpus(
        Path(args.out),
        per_type=args.per_type,
        negatives_per_type=args.negatives_per_type,
        seed=args.seed,
    )
    print(f"generated {count} synthetic documents in {args.out} (seed={args.seed})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
