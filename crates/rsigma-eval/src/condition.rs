use rsigma_parser::ConditionExpr;

/// AND `operand` into a rule `condition`, first or last. A condition that is
/// already an AND takes it as a new child, so filters and pipeline conditions
/// added to one rule widen the AND instead of nesting it one level each.
pub(crate) fn add_and_operand(condition: &mut ConditionExpr, operand: &ConditionExpr, first: bool) {
    if !matches!(condition, ConditionExpr::And(_)) {
        let original = std::mem::replace(condition, ConditionExpr::And(Vec::new()));
        *condition = ConditionExpr::And(vec![original]);
    }
    let ConditionExpr::And(children) = condition else {
        unreachable!("condition was made an AND above");
    };
    if first {
        children.insert(0, operand.clone());
    } else {
        children.push(operand.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(name: &str) -> ConditionExpr {
        ConditionExpr::Identifier(name.into())
    }

    #[test]
    fn wraps_a_condition_that_is_not_an_and() {
        let mut condition = ConditionExpr::Or(vec![id("a"), id("b")]);
        add_and_operand(&mut condition, &id("f"), false);
        assert_eq!(
            condition,
            ConditionExpr::And(vec![ConditionExpr::Or(vec![id("a"), id("b")]), id("f")])
        );
    }

    #[test]
    fn widens_an_and_at_either_end() {
        let mut condition = ConditionExpr::And(vec![id("a"), id("b")]);
        add_and_operand(&mut condition, &id("last"), false);
        add_and_operand(&mut condition, &id("first"), true);
        assert_eq!(
            condition,
            ConditionExpr::And(vec![id("first"), id("a"), id("b"), id("last")])
        );
    }
}
