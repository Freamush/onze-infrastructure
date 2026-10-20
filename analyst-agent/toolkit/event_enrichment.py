import xml.etree.ElementTree as ET

_FIELDS = {"TaskName", "SubjectUserName", "SubjectDomainName", "SubjectUserSid",
           "TaskContent", "ClientProcessId", "ParentProcessId"}


def _local(tag):
    return str(tag).split('}')[-1]


def extract_windows_eventdata(source):
    if not isinstance(source, str) or not source.lstrip().startswith('<'):
        return {}

    if len(source) > 131072:
        return {"_parse_status": "too_large"}
    try:
        root = ET.fromstring(source)
    except (ValueError, ET.ParseError, RecursionError):
        return {}
    result = {}
    for el in root.iter():
        if _local(el.tag) != "Data":
            continue
        key = el.attrib.get("Name")
        if key not in _FIELDS:
            continue
        value = el.text or ""
        result[key] = value[:250] if key != "TaskContent" else value[:65536]
    task = result.pop("TaskContent", "")
    if task and task.lstrip().startswith('<'):
        try:
            task_root = ET.fromstring(task)
            parsed = {}
            commands, arguments, action_types, class_ids = [], [], [], []
            for el in task_root.iter():
                tag = _local(el.tag)
                if tag in {"Exec", "ComHandler", "SendEmail", "ShowMessage"}:
                    action_types.append(tag)
                if tag == "Command" and el.text:
                    commands.append(el.text[:1000])
                elif tag == "Arguments" and el.text:
                    arguments.append(el.text[:1000])
                elif tag == "ClassId" and el.text:
                    class_ids.append(el.text[:200])
                elif tag in {"UserId", "LogonType", "RunLevel", "Hidden"} and el.text:
                    parsed["Task" + tag] = el.text[:1000]
            if commands:
                parsed["TaskCommand"] = commands[0]
                parsed["TaskCommands"] = commands[:10]
            if arguments:
                parsed["TaskArguments"] = arguments[:10]
            if action_types:
                parsed["TaskActionTypes"] = action_types[:12]
            if class_ids:
                parsed["TaskClassIds"] = class_ids[:10]
            result.update(parsed)
        except (ValueError, ET.ParseError, RecursionError):
            result["TaskContentParse"] = "invalid_or_incomplete_xml"
    elif task:
        result["TaskContentPreview"] = task[:240]
    return result
