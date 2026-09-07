VASP_REGISTRY = {

    "0x1111111111111111111111111111111111111111":
    {
        "name": "Demo Exchange Alpha",
        "type": "Centralized Exchange",
        "country": "Demo"
    },

    "0x2222222222222222222222222222222222222222":
    {
        "name": "Demo Exchange Beta",
        "type": "Virtual Asset Service Provider",
        "country": "Demo"
    },

    "0x3333333333333333333333333333333333333333":
    {
        "name": "Demo Exchange Gamma",
        "type": "Centralized Exchange",
        "country": "Demo"
    }
}


def identify_vasp_with_hops(
    trace_nodes
):

    results = []

    for node in trace_nodes:

        if isinstance(
            node,
            dict
        ):

            wallet = node.get(
                "wallet",
                ""
            ).lower()

            hop = node.get(
                "hop",
                0
            )

        else:

            wallet = str(
                node
            ).lower()

            hop = 0

        if wallet in VASP_REGISTRY:

            info = VASP_REGISTRY[
                wallet
            ]

            if hop == 1:

                confidence = 90

                evidence = [
                    "Direct fund-flow connection to identified service address",
                    "Association detected at Hop 1"
                ]

            elif hop == 2:

                confidence = 80

                evidence = [
                    "Fund-flow connection to identified service address",
                    "Association detected at Hop 2"
                ]

            else:

                confidence = 70

                evidence = [
                    "Indirect fund-flow connection",
                    f"Association detected at Hop {hop}"
                ]

            results.append(
                {
                    "wallet": wallet,
                    "name": info["name"],
                    "type": info["type"],
                    "country": info["country"],
                    "hop": hop,
                    "confidence": confidence,
                    "evidence": evidence
                }
            )

    return results


def analyze_vasp_associations(
    trace_nodes
):

    return identify_vasp_with_hops(
        trace_nodes
    )
