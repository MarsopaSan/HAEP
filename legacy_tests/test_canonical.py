from core.canonical import canonicalize


def test_canonicalization_is_order_independent():
    message_a = {"b": 2, "a": 1}
    message_b = {"a": 1, "b": 2}

    canonical_a = canonicalize(message_a)
    canonical_b = canonicalize(message_b)

    assert canonical_a == canonical_b
    assert canonical_a == b'{"a":1,"b":2}'


def test_canonicalization_returns_bytes():
    data = {"haep_version": "0.1", "message_type": "TEST"}
    result = canonicalize(data)

    assert isinstance(result, bytes)
    assert result.startswith(b"{")
    assert result.endswith(b"}")


def test_nested_object_is_sorted_recursively():
    data = {
        "z": 1,
        "a": {"y": True, "x": None},
    }

    result = canonicalize(data)
    assert result == b'{"a":{"x":null,"y":true},"z":1}'