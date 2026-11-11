# Risk policy v1

Risk is the maximum deterministic rule severity plus bounded correlation, distinct-technique, and anomaly-support bonuses. Correlation contributes only after same-tenant, entity-linked evidence falls inside the 15-minute window. Anomaly support is trained only on the relevant tenant's synthetic baseline, is never a primary high-confidence finding, is counted once only, and does not add a score bonus unless rule evidence is already correlated. Confidence is separate from risk; uncertainty records missing entity/time or anomaly evidence. Every recommendation is advisory only.
