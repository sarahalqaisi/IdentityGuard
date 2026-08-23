"""Directed identity graph and potential access-path analysis."""

from collections import Counter

import networkx as nx

from app.models import IdentityDataset, PrivilegePath


class IdentityGraph:
    def __init__(self, dataset: IdentityDataset):
        self.dataset = dataset
        self.graph = nx.DiGraph()
        self._build()

    def _build(self) -> None:
        for kind, records in (
            ("user", self.dataset.users),
            ("group", self.dataset.groups),
            ("role", self.dataset.roles),
            ("permission", self.dataset.permissions),
            ("resource", self.dataset.resources),
        ):
            for record in records:
                self.graph.add_node(record.id, kind=kind, label=getattr(record, "name", getattr(record, "username", record.id)))
        for collection, relation in (
            (self.dataset.user_groups, "member_of"),
            (self.dataset.nested_groups, "member_of"),
            (self.dataset.user_roles, "assigned_role"),
            (self.dataset.group_roles, "assigned_role"),
            (self.dataset.role_permissions, "grants"),
        ):
            for edge in collection:
                self.graph.add_edge(edge.source_id, edge.target_id, relation=relation)
        for permission in self.dataset.permissions:
            self.graph.add_edge(permission.id, permission.resource_id, relation="accesses")

    def paths_for_user(self, user_id: str) -> list[PrivilegePath]:
        if user_id not in self.graph or self.graph.nodes[user_id]["kind"] != "user":
            return []
        resources = {resource.id: resource for resource in self.dataset.resources}
        roles = {role.id: role for role in self.dataset.roles}
        paths: list[PrivilegePath] = []
        for target, resource in resources.items():
            if resource.sensitivity not in {"high", "critical"}:
                continue
            try:
                node_path = nx.shortest_path(self.graph, user_id, target)
            except nx.NetworkXNoPath:
                continue
            role_levels = [roles[node].privilege_level for node in node_path if node in roles]
            effective = max(role_levels, default=0)
            group_depth = sum(self.graph.nodes[node]["kind"] == "group" for node in node_path)
            paths.append(
                PrivilegePath(
                    path_nodes=node_path,
                    path_length=len(node_path) - 1,
                    source_identity=user_id,
                    target_resource=target,
                    effective_privilege=effective,
                    inheritance_depth=group_depth,
                    why_risky=(
                        f"Potential access path reaches a {resource.sensitivity}-sensitivity "
                        f"resource through {group_depth} group relationship(s)."
                    ),
                )
            )
        return sorted(paths, key=lambda path: (path.path_length, path.target_resource))

    def all_paths(self) -> list[PrivilegePath]:
        return [path for user in self.dataset.users for path in self.paths_for_user(user.id)]

    def shared_sensitive_roles(self) -> dict[str, list[str]]:
        role_users: dict[str, list[str]] = {}
        for user in self.dataset.users:
            for path in self.paths_for_user(user.id):
                for node in path.path_nodes:
                    if self.graph.nodes[node]["kind"] == "role":
                        role_users.setdefault(node, []).append(user.id)
        return {role: sorted(set(users)) for role, users in role_users.items() if len(set(users)) > 1}

    def high_impact_nodes(self, limit: int = 5) -> list[tuple[str, int]]:
        counts = Counter(node for path in self.all_paths() for node in path.path_nodes[1:-1])
        return counts.most_common(limit)
